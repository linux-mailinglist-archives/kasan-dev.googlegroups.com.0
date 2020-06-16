Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HZUL3QKGQE2ZHY7SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A53301FB0DB
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 14:36:57 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id b11sf13420678ioh.22
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 05:36:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592311016; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZGLL+skiWN/Z2PRZbNp/8aJsGTTfl/wV397u3qP+64Eo2Pong3XABHqTRWmMsPW4PZ
         sDoOW3S1n7J4wJNGEHEChYkYeR0wA6J0uDgI6Lx3BrSZSp3yptyKyg/yUF2NzqCLmJ2b
         I+qH7XUYiWzZg+9OsVAwSRRnU7XcuO1VHWO9vmxgAr1s2Q+vc/rBCXzj68rR8/xBtEYJ
         wSR7MeVlasibxA6vGitNDoZLD80FzfA5iyMS08YQyydh7lQne38UsF+r1KRbVhpxpkLD
         CrrVnUGU5maPw5Nvxm0cnxGkWppm5pyAwqU21XvA1Hxpu2U2tVvHbrrBXAfH8c+5ba4j
         vqJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=07oipE+ajYFpo1ku3nM0EtbnHtgzN6p8Dp+6Dty2EsQ=;
        b=PcNtDuvcmyfrdjnIoM7bhs5sJXw8vzCNOFYjB36SwW5HBsrud3hgW5VlJubixvyVrc
         guXythR22W/CbTYaOq7WYD2zMj9I6lZL49lyiobbdxKH0n5lbcWDXTJ0gLjVmBfXr9eT
         SD/JMTBwp94DjAAbh55mrNtrQD5xGuPz0SCmnFjABh2cHcn/MNeISYpV7ApJomkaAMZw
         k7QgKNtaRRDZnDk+arG42KrQ3bVsh20K13wohW0CdMCdL4Xw40qMKSAI9E2FVYyv2CZC
         i4I0aDH+ZXl2q+l1c6OyQqodCNpAxKQ1f311M8iSjoAsdDM4Hw6XjXz5vJg7K8NfWf5X
         +8UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=giq6ndmK;
       spf=pass (google.com: domain of 357zoxgukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=357zoXgUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=07oipE+ajYFpo1ku3nM0EtbnHtgzN6p8Dp+6Dty2EsQ=;
        b=k+2z0yT5iwxOJHsnIO1vzRhGGsDMyueoKgei2SybOb7uU1z0NmNZFwb/3FiDNrE88g
         KoII+4IFJARTVlilDIgWfPeUU8HyJQPLSubfavZMZPcXaZm22nA4WCQGqL1HBkk+fzK6
         d97KTVwFNSrCLljva2YFdlV/ZU5Uo0AdtinmZFnYOxyWIopvhcQD4m9Sg53tcCiJZntP
         SfDb5hgO60Cx2DcwhhR1u7EmfBmwOqxOeBoDLyFfaHPiGfnEaPx5DulxF0tnBo9F8zMF
         xX6TcnoCs31zdA7+PxYS2kbPJykjJYdOaZIzzPLtdLlOKrsuzJaBbI40GkPABG7iApQv
         tKYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=07oipE+ajYFpo1ku3nM0EtbnHtgzN6p8Dp+6Dty2EsQ=;
        b=thrBpzEDtwJJSNeLosuobJ77pV3CezrGoc10d4EHYJAIy7T0WEZ379D9qvIkmN9ioP
         b41Xw+jUvt6C0RqDx0uay2kADpJIc41/blfanyZUojGMXvnAJhG4m9oKudluOxNhbdJ+
         F6LQAOGOW1ltUOR97yaaSvhZE5n8zlI6QegexLL0TIXDJtb/kA57CD0URzIr9i5d/w00
         BPmE9JHAfw58pBlUiw79OVrYYM4AoK2gBKmJSY9XhcTpw7Zmmo0xtvLyaAxpYVK96arM
         NqrQmg4y2uUHNt6oWnQXPAywav2t6J/kg+NyxAPHwg8SLaji3Vj4U+ReB6C7tbdiz2X3
         cKxg==
X-Gm-Message-State: AOAM533V8pCHf6oD58K58HlIOVDC9cY04dnimRsJZTDg5Mh9MWqDQdOZ
	BXVX1DDLSASaXAiDlWB2gzg=
X-Google-Smtp-Source: ABdhPJzT6KZvKBPjDMiXU9FcbFWY0/e/tpfDam58EuTPABjjIr1cgrPm1B8lvohr33dqLO3kFzAw8A==
X-Received: by 2002:a92:9603:: with SMTP id g3mr3019753ilh.204.1592311016476;
        Tue, 16 Jun 2020 05:36:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:228b:: with SMTP id y11ls2216061jas.10.gmail; Tue,
 16 Jun 2020 05:36:56 -0700 (PDT)
X-Received: by 2002:a02:6c8f:: with SMTP id w137mr26660081jab.38.1592311016103;
        Tue, 16 Jun 2020 05:36:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592311016; cv=none;
        d=google.com; s=arc-20160816;
        b=iaOyEt0RpeDBUjro+q/jS2YcDBvuXiXFQmakxldYnrG28W5qlwzfyovekUEi/CF4T1
         e1ohkIwlrMdi6OPawWSHIxonkj0CNjL3C+rC7DeEErFSf05gNSf0bMh+Yc42OowqvfMN
         LyYep5VIGl1pK3HVjU1LmNb/CLP4DAVdjfSyJ520OMxBA3DJD+hpyEMCrgi+x2XfkaFm
         BM+8z1VYL/Tw8ZObZk/WdqqCS30O/0pwURiMQuPbucPVVzSUCSSVxQ6R7AT6TTXIX8hm
         pUUEbWmXto9obre2hJ0P5/i/NejAvDP1C+nLqgD/xOf2fSQ6rh3US4sudJjIMBJKpY/0
         5GOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0vKWPfQjP4gTkC13b5eOTjKj/nU6f1wDicpnc57zvTg=;
        b=kamPe34bDGEbTkqhwkxiI81xDV+oK7S1q28/nufrZZbJTvVUagkPNZBnQs2vrXJZqt
         Fg+Ofxv+80GIwENAG1zH3yZsN58YMiaq8JKE0wprsxgaJ4vPAtv8qdOBvvusFjz4qQHf
         yjVyX00X89Dy1qX+vcy8hWM3wqBCVXkMHHvJgoWbKF6o76pMkP1zLaTmjS9a6UpJPzOH
         KN2QJ7rlsUg5hvXDiAozBIbtLMFpNzTO9T07KO303bHdAicWgo9Z0j61bpyNVKXr7iLb
         W4P7Dkfrllj2CZggs7cTEXOGcZoZABTDMOl0TVNFZIRRh91R2KUaKHJ7ECwOn4iDU3cd
         LarA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=giq6ndmK;
       spf=pass (google.com: domain of 357zoxgukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=357zoXgUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id b1si1037789ilq.4.2020.06.16.05.36.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Jun 2020 05:36:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 357zoxgukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id s20so15423228qvw.12
        for <kasan-dev@googlegroups.com>; Tue, 16 Jun 2020 05:36:56 -0700 (PDT)
X-Received: by 2002:ad4:472f:: with SMTP id l15mr2030266qvz.52.1592311015499;
 Tue, 16 Jun 2020 05:36:55 -0700 (PDT)
Date: Tue, 16 Jun 2020 14:36:22 +0200
In-Reply-To: <20200616123625.188905-1-elver@google.com>
Message-Id: <20200616123625.188905-2-elver@google.com>
Mime-Version: 1.0
References: <20200616123625.188905-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 1/4] kcsan: Silence -Wmissing-prototypes warning with W=1
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=giq6ndmK;       spf=pass
 (google.com: domain of 357zoxgukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=357zoXgUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

The functions here should not be forward declared for explicit use
elsewhere in the kernel, as they should only be emitted by the compiler
due to sanitizer instrumentation.  Add forward declarations a line above
their definition to shut up warnings in W=1 builds.

Link: https://lkml.kernel.org/r/202006060103.jSCpnV1g%lkp@intel.com
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 15f67949d11e..1866bafda4fd 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -754,6 +754,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
  */
 
 #define DEFINE_TSAN_READ_WRITE(size)                                           \
+	void __tsan_read##size(void *ptr);                                     \
 	void __tsan_read##size(void *ptr)                                      \
 	{                                                                      \
 		check_access(ptr, size, 0);                                    \
@@ -762,6 +763,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	void __tsan_unaligned_read##size(void *ptr)                            \
 		__alias(__tsan_read##size);                                    \
 	EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
+	void __tsan_write##size(void *ptr);                                    \
 	void __tsan_write##size(void *ptr)                                     \
 	{                                                                      \
 		check_access(ptr, size, KCSAN_ACCESS_WRITE);                   \
@@ -777,12 +779,14 @@ DEFINE_TSAN_READ_WRITE(4);
 DEFINE_TSAN_READ_WRITE(8);
 DEFINE_TSAN_READ_WRITE(16);
 
+void __tsan_read_range(void *ptr, size_t size);
 void __tsan_read_range(void *ptr, size_t size)
 {
 	check_access(ptr, size, 0);
 }
 EXPORT_SYMBOL(__tsan_read_range);
 
+void __tsan_write_range(void *ptr, size_t size);
 void __tsan_write_range(void *ptr, size_t size)
 {
 	check_access(ptr, size, KCSAN_ACCESS_WRITE);
@@ -799,6 +803,7 @@ EXPORT_SYMBOL(__tsan_write_range);
  * the size-check of compiletime_assert_rwonce_type().
  */
 #define DEFINE_TSAN_VOLATILE_READ_WRITE(size)                                  \
+	void __tsan_volatile_read##size(void *ptr);                            \
 	void __tsan_volatile_read##size(void *ptr)                             \
 	{                                                                      \
 		const bool is_atomic = size <= sizeof(long long) &&            \
@@ -811,6 +816,7 @@ EXPORT_SYMBOL(__tsan_write_range);
 	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
 		__alias(__tsan_volatile_read##size);                           \
 	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
+	void __tsan_volatile_write##size(void *ptr);                           \
 	void __tsan_volatile_write##size(void *ptr)                            \
 	{                                                                      \
 		const bool is_atomic = size <= sizeof(long long) &&            \
@@ -836,14 +842,17 @@ DEFINE_TSAN_VOLATILE_READ_WRITE(16);
  * The below are not required by KCSAN, but can still be emitted by the
  * compiler.
  */
+void __tsan_func_entry(void *call_pc);
 void __tsan_func_entry(void *call_pc)
 {
 }
 EXPORT_SYMBOL(__tsan_func_entry);
+void __tsan_func_exit(void);
 void __tsan_func_exit(void)
 {
 }
 EXPORT_SYMBOL(__tsan_func_exit);
+void __tsan_init(void);
 void __tsan_init(void)
 {
 }
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616123625.188905-2-elver%40google.com.
