Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3XOW64QMGQEQDR7GMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 99DB59C1C3B
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 12:35:11 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-539e5f9df25sf1180112e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 03:35:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731065711; cv=pass;
        d=google.com; s=arc-20240605;
        b=K34CNenHyBaiWTyerdN8moLsj8tO+7mWGcnVxqXR/5EMFAv6/0/ag+d2QSRcdvFAMI
         D0yyXIbNcb5yOAHUgZeS5CDUrDPg7mRTG/UUUE+6xfJKSV/d0nioIXDRtnGO+Km2Itcd
         UQe9FS3ajGdYmcVeaDmI7qvB1VO6QvGwE8KuBHvWMJAoK3gez39rU67KRWWyc8gbl3RK
         1zyOY6UGv5WxLvMUfWXxUzOcqrov5mZiF1zSlmNrMSATMAcUWotPUHRXbBZFEy27rDSX
         08CgrWMiQKKZi/5UeFx2ihrF1E5WRojMkjdJOFO+a9PaK4YuDhLl086On1x2okCWvVAC
         ACbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Bo23BjgTEf04bZdF+mwX4hhUaXUBOE3X3f81OUB2ido=;
        fh=3mmJ3N5furxid4ebBJBv8x7BgEX6Xh4WrOPp5I1PJ7U=;
        b=DBuHwcczWsC02aUpMWCoyl/eiARUam/zDoIZah/93AbKfeDroAtHF9L2WxNBIxTu5C
         AhUePKzOt3S4XoYAiZd3zqABkn2ZHnlPYWcA6S+JFpRY6Iu2mnA5NrCVAkQ3zKMJ/2N1
         GX9pUqF8Kx56HyqG/Zw7x+CO38WGEzHDCV1vG/YYOSom2CO8xTZGJPOlsRMIMVzDM8/G
         fJCwqCRIjd0XybclUYzECFR3agjCyJ5DKdTRZQJe47P/ujOghUiuRwM4xuPONfKdpkWa
         XaB2SW/T0DJwNn7HFJzsQqOCjVKfFDJRZB53XeFwqqv2mbYxgrEWGJYPH2hjNM69DNUF
         Pj1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Lq8+vF1r;
       spf=pass (google.com: domain of 3a_ctzwukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3a_ctZwUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731065711; x=1731670511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Bo23BjgTEf04bZdF+mwX4hhUaXUBOE3X3f81OUB2ido=;
        b=RnSWrLvbGgT2Gz7zaFtnQGWRvUbljGLXyLLwKUPrS8EoW7tOOtwEKu3DXVsxDOSKzk
         GF/s8Frgv8gaNcoesZJZGC+EABeMsuB8YiTzYG6sXh0HgC7O3X1lQNsJ+RovfPLPi9G7
         AQgBuKScNX1GuAxYLMp1i8LpR22NlaIH6/pBiU1qYRptb3QzrFW+2d9R1PLEdRjvXdwC
         VjtHXvabj2ikmxtVL2H1gXSd4PcCggjpVwalk7bOs9gMXIPhLfijhz063qb0GHnmo2sg
         a+2NNZQV8xsyww5Bv9gh0A1skB+aT6xppgvpZBJ3qsKDDHlWNj+V6HFKmQGtR4qR8iSF
         Qlfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731065711; x=1731670511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bo23BjgTEf04bZdF+mwX4hhUaXUBOE3X3f81OUB2ido=;
        b=nYlbFPDvwJydKiNKsJWjYoLrl3fzf9LowkrpOK7vu80vNc12C58utkCqz4sTvbU6pA
         WC8S9QDuRus4R6GeeTDYsvHjZCflo/U8mjb40VsPBcYLwIzocqBcT7UmqrMRmMmZkj9+
         doikMUSyp5ZSa+/UW2covn42NwpCSERwpq/VlqLWOotkQP4Ji+v20/lWYJ4swOUSFXTp
         LZisxPTomHTozfW02SPdF4Z/86iMsIHw7SEiRU/gxfHhuv5fVfih6GwnTrpfPG/tS5HE
         45EegeOAsDYp+fV5uEw38gSS4aoxxo1vmyk9juMEOKKplyq39Sl05GLfYz0P9ISva958
         WZYA==
X-Forwarded-Encrypted: i=2; AJvYcCWzN7EAXxON/B57p5C0ezX7gRZujLHh4yL37f/LOK1czHdfLv4PNjWqNnjdUDiJFNoIe9Au+A==@lfdr.de
X-Gm-Message-State: AOJu0YxX+B6E802EYp0zZ4jemi7wcXd2OUmIyIA4m+DMGhCzuAOiW4YI
	kVtL06ocQzFNVmhj/wt4C1rcmjseBU03jcXVhO0uHPMzLlDZ/VSg
X-Google-Smtp-Source: AGHT+IFnGi5bySQsxbaXfDsP1d3cGndwm+thqsSHxSLkryckwB4GNgrsnNSqtE7xg5Pg1FW1/Cpx6Q==
X-Received: by 2002:a05:6512:e8d:b0:539:f65b:401 with SMTP id 2adb3069b0e04-53d862f805amr1138301e87.57.1731065710385;
        Fri, 08 Nov 2024 03:35:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:acf:b0:53c:7504:2ddc with SMTP id
 2adb3069b0e04-53d8177eda3ls105173e87.1.-pod-prod-08-eu; Fri, 08 Nov 2024
 03:35:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWi0HDBxbE63W7MT5bNwSxSZertC8Dmh6AnCStsOLotdE+dUQPjWekzwaL/CfUrdnURABCShYtE1zk=@googlegroups.com
X-Received: by 2002:a05:6512:ac7:b0:539:efdb:4324 with SMTP id 2adb3069b0e04-53d862c6fd5mr1594067e87.21.1731065707747;
        Fri, 08 Nov 2024 03:35:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731065707; cv=none;
        d=google.com; s=arc-20240605;
        b=kx/4k9mjmIhovhq+6ls+TloknglcYij45YyayBnfCPeOGNUDpfdUG6oO+PnIFO9ZK0
         VHJQ5NQx8LtTmGIdHL35KefBHHA4bEVcFPPAmUOFrnbZFTcnfV+bUxA8rrofXtoOEPEH
         tRnVm/C54JH0fyOi8x6DIo4NNz6037ESdPiFsTTCvbGeJxKs09knETwhFIUAzY8X7Wkw
         HpgAjgfVjZpsR1HMolfTEPYppib+jz4b+8zfeDAg5xEiGpu/Rzz0dUAgwfSHXmxO5e1L
         FDp1LlP8fITH3q0c/Ion0cokDsE2Idv+hi8KNGQviV9pkTkSsD2rLRRzy8eydW/kb/rR
         zKpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=WmVAOqvZ/Tu1S1PwD7c/mNbANvvbo6/nc3HYAPUr/Js=;
        fh=4YdmEqJBO1VenPlSG9YqiZQKkE89xK7ahLRQIrSihzk=;
        b=ScrZlXMG7YZ27yveUj4vF4Lm6GbzavHskRKoTMN3msytIFmOHJlSthtVMIPEUMDA23
         UATbkqS4xIMChA63NE14G/ZjSdO7iaUqUqFCD/vsYcHyemF7l/NG7iIUShfgFPFSy+iA
         ComRnjkQeqnQUCiiVZy3qK2uBk7qDz6FV1ydVUcX1IMKoDWJXlNEYCO6WPTDi1ZdyQFo
         W76FrJ3iGIQzdpYIQCvrpiX5fPPNcGZBehnY0hTpFszaYgYVRQ5uyWxXzuiKB53NVLzK
         RX72t93vl9GgvOYSIuzltl6PiNQWbWGck2g+JWGVA54Y2PvgNvxwoEI9Suz75XvSxQWN
         LDVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Lq8+vF1r;
       spf=pass (google.com: domain of 3a_ctzwukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3a_ctZwUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a3688807si3857905e9.1.2024.11.08.03.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Nov 2024 03:35:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3a_ctzwukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-a99fa9f0c25so152857966b.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Nov 2024 03:35:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVYTEj2MBr+HT7fdUEbYPHde9ewLalyiDIGuUdBPt6S6bPGkDWOWkF1FRVg8IUsKaovcNtP7GOm48A=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:1d41:9aa5:8c04:911])
 (user=elver job=sendgmr) by 2002:a17:906:2557:b0:a9a:1769:f4db with SMTP id
 a640c23a62f3a-a9eeff38838mr49766b.5.1731065707141; Fri, 08 Nov 2024 03:35:07
 -0800 (PST)
Date: Fri,  8 Nov 2024 12:34:25 +0100
In-Reply-To: <20241108113455.2924361-1-elver@google.com>
Mime-Version: 1.0
References: <20241108113455.2924361-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.277.g8800431eea-goog
Message-ID: <20241108113455.2924361-2-elver@google.com>
Subject: [PATCH v3 2/2] tracing: Remove pid in task_rename tracing output
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Steven Rostedt <rostedt@goodmis.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Masami Hiramatsu <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>, 
	linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Lq8+vF1r;       spf=pass
 (google.com: domain of 3a_ctzwukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3a_ctZwUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Remove pid in task_rename tracepoint output, since that tracepoint only
deals with the current task, and is printed by default. This also saves
some space in the entry and avoids wasted padding.

Link: https://lkml.kernel.org/r/20241105120247.596a0dc9@gandalf.local.home
Suggested-by: Steven Rostedt <rostedt@goodmis.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch
---
 include/trace/events/task.h | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/include/trace/events/task.h b/include/trace/events/task.h
index 209d315852fb..af535b053033 100644
--- a/include/trace/events/task.h
+++ b/include/trace/events/task.h
@@ -38,22 +38,19 @@ TRACE_EVENT(task_rename,
 	TP_ARGS(task, comm),
 
 	TP_STRUCT__entry(
-		__field(	pid_t,	pid)
 		__array(	char, oldcomm,  TASK_COMM_LEN)
 		__array(	char, newcomm,  TASK_COMM_LEN)
 		__field(	short,	oom_score_adj)
 	),
 
 	TP_fast_assign(
-		__entry->pid = task->pid;
 		memcpy(entry->oldcomm, task->comm, TASK_COMM_LEN);
 		strscpy(entry->newcomm, comm, TASK_COMM_LEN);
 		__entry->oom_score_adj = task->signal->oom_score_adj;
 	),
 
-	TP_printk("pid=%d oldcomm=%s newcomm=%s oom_score_adj=%hd",
-		__entry->pid, __entry->oldcomm,
-		__entry->newcomm, __entry->oom_score_adj)
+	TP_printk("oldcomm=%s newcomm=%s oom_score_adj=%hd",
+		  __entry->oldcomm, __entry->newcomm, __entry->oom_score_adj)
 );
 
 /**
-- 
2.47.0.277.g8800431eea-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241108113455.2924361-2-elver%40google.com.
