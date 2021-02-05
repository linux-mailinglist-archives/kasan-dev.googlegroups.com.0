Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRGN6WAAMGQE65VB72Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 480D4310D45
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:49 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id l16sf4133395ion.8
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539588; cv=pass;
        d=google.com; s=arc-20160816;
        b=kUscGDjfZLZ7KDowkfQghCpTU6672iTVhVag9Zh+yeYAiaQYLOZPj8Iw9vnKSSzwVh
         ucKCqBYP8cG9MAmVhaXFi7cMnIjXx//+VGV5nYfaZwtd973VBTVCjaA9vQAex0AcO6rE
         tOlFTNsNbinPpmijBwp7zUmXZi/eRWRJtSQyD4wlwuAyMGNU2ONmKu4n+BgoOSyxuKeu
         WuZHeBLSvHDwPUqju8CwvWc/Zp27gFG2IIUWsz4DfAuscmwhTbaNB3KNaPWTWMyBvvmr
         EI0fWAMpKRBRBZvI2zYzgTbdoxpVCpYYbh35DrWZVBEievw8h/J9HggQ3QNQIeGRtKsd
         ToBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=n44s2OGI4IZBszkeQtT2kA7xMVy/CVuhdcrmJxeXXRo=;
        b=IT+UzUYxSHVMn+6TckM2R8lU2zfGe4Hy5vaFAc+AF+A3H96aWnA5kyWkjeuzq3vjEr
         9EXI+De5wZmBxrsLDHNtwvOpQ2KhRHcxylabWcaMIY1OS06pQg5QSJr4SK90FXqZjrId
         IGj02oFK7A79Lf9gQDf4Ok2EgRJVp5dfHhx/EHp0FspdDlhNnWuqJmL53IHgmHja46MS
         9vPjbO6igsJtHzXj72TYfdSIvOL9leAf/hEJW+2vwUMB8nZs/AMOR6dZ4m9um1oiCYdv
         D4Vuf+lULQIlCVg4qTjBPntFDj3HohNp0aSHBJ/ii2xAvl2wrfHBWHHWgMlByM3VgSsl
         iFCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gxafKVSj;
       spf=pass (google.com: domain of 3w2ydyaokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3w2YdYAoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=n44s2OGI4IZBszkeQtT2kA7xMVy/CVuhdcrmJxeXXRo=;
        b=rYIFrmxKdxPLO16Ax+iqYi8lj1O+jgom9vkbNv0X+VAoOW6x68osNtrINnrOSRrMHq
         kbbgMLHzadWQL1etrCJnw4QVRbwHlcX2g40BbuIQdbm9ms1pSA7ks9nffDxLFSxo177A
         0jMfFDBPllSsCXe5lvJk1yD5wZFeU1iPJSdQkTCXfbHrcHg/wZm9leCTd2Zw9vV0BqW3
         Bb+pNik5sxb8lTBKe6YYATdk68CD3GI9Vc1APbb6soDhOl8xvzTVUj1Ug5w/NadhWdKe
         OlclaDr/g1lqB8sVH/AQn3woQ8DOBihHFAoWr8TZqvTn+r2A5yZIYf9kjINECk8Wk0wa
         AI3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n44s2OGI4IZBszkeQtT2kA7xMVy/CVuhdcrmJxeXXRo=;
        b=aZMyvkr+9vmnxYynpYgakeXN6IHABt01fZ30jn4GG2ZxEqhjnfq9Z/rjrRcn59kgO7
         eFHfot/qqn2Qsof8EgUT5WTNYElH4EuTXlSANhZgQHPwUXB7f/6SAdbKBd2OFFZ929eR
         MHmJj8IJzpu3cn3JIZHU/+VNp0u7MuaKt5TKnTMh3eKvtsd5qNaNm0XL7AC30UJ5b/kG
         oMS8K4aeOhPbWkadVMPJ/tD5Ua4MMcZYa3+Gl8rs2Xxn9q21kQPinTGEMpAC7u53JKQH
         Iijt8PVdyhcY8uDVssBxaHd+/soWH6yeuysO3s7RLeESm1mqTZZWs4zlhHzd6f+Ha81q
         wDCQ==
X-Gm-Message-State: AOAM532HJ4cjCUwA6Xkopzv+1ngP3lXd4aLYRniURd1Z9Ns63yWzlEv/
	QUxKCovgn9NTGqz2B68mLh4=
X-Google-Smtp-Source: ABdhPJytImEvqJQkZZrba1gIw4KPn5NfoasvltlFGrsfwDhUNLh7dzWrDyS/Y3A/TCIF6icJWMMy0A==
X-Received: by 2002:a05:6602:24d4:: with SMTP id h20mr4442629ioe.64.1612539588311;
        Fri, 05 Feb 2021 07:39:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7f0f:: with SMTP id a15ls2353351ild.8.gmail; Fri, 05 Feb
 2021 07:39:47 -0800 (PST)
X-Received: by 2002:a92:db51:: with SMTP id w17mr4397631ilq.107.1612539587867;
        Fri, 05 Feb 2021 07:39:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539587; cv=none;
        d=google.com; s=arc-20160816;
        b=AdooD24g4DYePwEuZCOb3++qXMbg06EGs33hhgG9K8oKvOjoqP05DwM2OEtf1rweqU
         aluxJVdA+FLjoQWQH1lyFh/8M7HFDNeRyPN0mtfFw3z6sDNjDB2uBJAmeEtRRS6RRlFL
         095VCDupOjN22MvrO6Z1bfgXilrvgBdGha+0VwD0YPkb5gKWaIa8bqawdqsS45OjKW1S
         Kft6uOm5R2KEY5wUPmbvd6kZoRSaoJnIP++AxTFJ3Rzy8i13OICl7KQVPO+W4/pK7xM6
         J506AsgFyZo94k9u71fVeQ29hjbcN7/v7Wk3zLYw8VCU5wqnmawEdMh2N9fu06jAADk8
         rIKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=jIaeLYAzRLuX+Bh9Y7uHrxQjgj3fqKxlpOgYc1EJ990=;
        b=mplbUib+DQg4OyDsaLgbCuz9FlWbtieFr8hJBc/fAS7grjOUDzqjcVay4Y8MSM8GGf
         D8Qcax0WIg7VtWH1UGI+goKCxSyxvE8vXpqjg+lnrFupogcRz9zM5snZU2gjKZeHFTOA
         8vLbKqfmfjJ3EOLX1PBY994rnet3W7sTYW2r8EsJhAJxTNzYuRpE1JeMdGeFW8UuOjEA
         8P+4LjEQPFTpnMtlZbiZzNiWL4dfqHVn+Z9qWPF51eXKlvT31CFJTVSJcnRiVZ2aH9HD
         cIncCdX092YOZHUB7LiXu+L96mVTpKV3t4qO60kpt7WAgmJjjqqHJCkyYkI/mV9pp42r
         lNyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gxafKVSj;
       spf=pass (google.com: domain of 3w2ydyaokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3w2YdYAoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id f11si539959iov.1.2021.02.05.07.39.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3w2ydyaokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id c12so7432950ybf.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:47 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a25:31c3:: with SMTP id
 x186mr6809008ybx.500.1612539587288; Fri, 05 Feb 2021 07:39:47 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:13 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <068ab897dc5e73d4a8d7c919b84339216c2f99da.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 12/12] arm64: kasan: export MTE symbols for KASAN tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gxafKVSj;       spf=pass
 (google.com: domain of 3w2ydyaokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3w2YdYAoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Export mte_enable_kernel_sync() and mte_set_report_once() to fix:

ERROR: modpost: "mte_enable_kernel_sync" [lib/test_kasan.ko] undefined!
ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/kernel/mte.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 8b27b70e1aac..fc753fb77940 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -120,6 +120,7 @@ void mte_enable_kernel_sync(void)
 {
 	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
 }
+EXPORT_SYMBOL_GPL(mte_enable_kernel_sync);
 
 void mte_enable_kernel_async(void)
 {
@@ -130,6 +131,7 @@ void mte_set_report_once(bool state)
 {
 	WRITE_ONCE(report_fault_once, state);
 }
+EXPORT_SYMBOL_GPL(mte_set_report_once);
 
 bool mte_report_once(void)
 {
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/068ab897dc5e73d4a8d7c919b84339216c2f99da.1612538932.git.andreyknvl%40google.com.
