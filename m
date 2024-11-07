Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEXEWK4QMGQE6GRW7VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id CD0A19C05B5
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 13:27:00 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-539f7abe2e6sf659671e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 04:27:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730982420; cv=pass;
        d=google.com; s=arc-20240605;
        b=kXqQmgwbLJW9yIaFrlh9lJrtYmMi4YoGrlRWXZb+AeURXqvw2t3Ib6GLoyL9cugNl8
         8eICS4TifXzGac8taq0Z5OJKLk0AbZlYu9gnecHOcMneMwi3tB8w3xLLcBH2l1ofOW1x
         uW/wol1YVmY5HcXzl7idy1iB5L6xseFVrz3oBDRjSXFJ8noMwvoJvjMVemwlu3gXElfu
         U8mD6QDcGp3iz6qeNtuHKq5cw4wGu3dYit5bVf2gDM9tqBdmYr11wUXMAhsqWDuRcisU
         +MnS0YslUA6C/oc1R+xdT/KC06vJ5lEqz8fHj4fM00pxXHjD0k4KAL8TSzBgLh1ACJ9w
         wmkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tEikAERMqNwyJOJUScoBhVWMf5FNI33BeoZNz1mtUYE=;
        fh=W1yg8Cq9vrl/MpKacPjEC0XiHk/BsXVCIn2nE9OR2Ic=;
        b=PLRfkk4dz+ugf9XcdzrrRwVk+dZusb6m1OUBOUyJFsgV29DgGFo88/RvvGFpTaPqsj
         YUjAOX0dqkYHfkIEbpETtlYnrZSCpynsglSAArZ9KUYLstvRAXuDrJH1nXMlnpSk/9hE
         1GAFTaNpElStRMFSbhGWG9qhHtVEGRdSbOK5q7t0UqhXC0+FeE8Yi4L+OY6dxtHdcDBs
         QPz0fuQPIw9g4yBGE+cUWezBci59tBzMZxinqg8EXDidqyvTdYWhcSFW8MyQlOzXB+B/
         QhyThbYc2S6L/qSVx9ZA2TEoGt0BBJi61USiVxFh5WGZVVIakzpTrSKUs11tLRHpNEGq
         57bg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="t9a//lbd";
       spf=pass (google.com: domain of 3eliszwukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ELIsZwUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730982420; x=1731587220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tEikAERMqNwyJOJUScoBhVWMf5FNI33BeoZNz1mtUYE=;
        b=i1auxcCaXmV9P1gqxGWA5osJsSkdS2u3pSocVtiLV38wfcATmQ1vVqbIguxMp1Skbh
         uJxbVW9Q2+yxmSYRJ5d8AYcUN1wLdpzmI9WhzooB8q23EXnO7Z5Gz3WIb21vTVBE78zl
         zaMTshQGx+ogBlSCTNVGINCW+w0G2iWc2gBbiQtJnNMezZqBOybU5qMReoVM8bSgIfrj
         pbcViFRYTHjaODKVju79KbxQ097yYZkqL3/eGyg+Zk2402eEVpaOfwSHtZi3e8gE02dr
         o5fJYGedmV+cSO5jvk/Riw0raktqTjYltAuWJbcx0CyEmCkJnipYt5xzpJYnMc5/CJqt
         q9XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730982420; x=1731587220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tEikAERMqNwyJOJUScoBhVWMf5FNI33BeoZNz1mtUYE=;
        b=h40PSC+SCYc2o0rnWoq2w0Ca2JxZYUV9a7eRPK4IWfjXjjfFR20dFa8Cxv/c5/o1QC
         kDoXAg1fIMhAIPtCQmx+1X/Y7J28Gft+erW1Z6J6ZiTQN3cW2Gep5Qu7PXnkG2UQbkgx
         mspzda2wqIsFufUek6sos48bNltNYuyldM8Qq+0u1HBPyM52fczvpFJ9g3KeFSaHMfL9
         ATqajMaQkZP346b3z8OqyVX5TuTw3R0brLI+cEextMZ5KWaBvZNdMg55BIYM2W8s+7O2
         ygFfwHWtbU2Nd7rKZ035vLlj29e10M1YCklj28AWJPnTio7QrlA/7Y1CIYjwhsJxBPMe
         Y3Qw==
X-Forwarded-Encrypted: i=2; AJvYcCUHsxInu/eJ9JShNVaBK/tRMeqGB4C0TaVdwXUn1SZ6ozf+cdQ8ZhRolipD+LzsqA9OL4J1/w==@lfdr.de
X-Gm-Message-State: AOJu0YwLEOuGhl9NbInRgy2vZ/JH+EL5TialTR3mi227NVSWbMlGa5G9
	GVntwa/KmP0QCVk00sd1F2DJ8MCiFWJJl+mfr4Kt77rAncRGX5cK
X-Google-Smtp-Source: AGHT+IGLsbv5Iy+yEFZIOV0whzg9Vlc4Mi0LMU7UxN5oKb0eqIjB+MlmjydmRQv8pomuvfRM/R6tEQ==
X-Received: by 2002:a05:6512:2208:b0:539:fbf7:38d1 with SMTP id 2adb3069b0e04-53d84070109mr570992e87.2.1730982419328;
        Thu, 07 Nov 2024 04:26:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:a49:b0:431:9388:1f72 with SMTP id
 5b1f17b1804b1-432af02d2f1ls3547195e9.2.-pod-prod-01-eu; Thu, 07 Nov 2024
 04:26:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVPUc2nmjWqC2azUljbJmm87kEkfK5K5fcoOodm7jEKFI5pjag6zCoWjLoNxEhLXisVUNmKEhWhB+g=@googlegroups.com
X-Received: by 2002:a05:600c:1d1c:b0:431:5a93:4e3c with SMTP id 5b1f17b1804b1-432b301ecdemr10147655e9.16.1730982416597;
        Thu, 07 Nov 2024 04:26:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730982416; cv=none;
        d=google.com; s=arc-20240605;
        b=IcVA6FEADkM8UM8RE7BwpcF6bbc81uczqbasZB90RnLHz4P+ChaCKxBPxwKPgaYL0q
         DFUIHn5E0wGTRfFVrxcE67d44xvyx8dGlsWpURiJ5gEc7LS4Th8ZymveGGkl2CQ5+3gk
         538CBl+tqn7DFoScrGG3/k/y2IVgXIMcCRG/fAbWj6/jYejtYNJdPB7FLWbqhdJSU6sj
         My9LAYfSUDqkoHF5yBYqswKl8XTF3T6/4JqogxcYHDmG+R084GUX+Pgj/rq7eaLmnMX1
         aHpqScoob+tte2tFgIL9oBBXm2Lj6FYe8hnKSEYGQAVNW/W80ym6dn3XoZMR7CQ0/fQJ
         pDow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=9sHGNL7Z8k+ba9HHh8eNNDPID0xL9oZVgVqMixfCZM0=;
        fh=UMDFJ0JBTbY1ISJt+fZDPEtjO/5tf4JaEdPQEZjxQ9g=;
        b=jncGvC6zvOE+nKbCbkbczbTZAXElPyyYWtLWxk6wSdwD42xYePsjyxPHib6FNAlEZh
         tYqfNlnwRMLuE/YRUcW601hXvKzsoV5y5tJKhMRuY4h+P+ORYos2oU5liA/zORTe1QRx
         T2mIb79iRXpJxLvFxCj7DmR+yqj1XwNVMorlD8CS91Ky99ZofGFjuKi4gtp0YNKOdaAk
         XiURErPqv6N6EGmJO9uwuLh/nTPirrCsFHFd8rLJIrCSq2l8stXqf9eRakR7LyWE+lzV
         hVKY+SxJ+4jNemtXEx+IeXwo5xCqCZP/JCb8WNJc+qL479j7lYD7nESMGgVjBkzWdVuN
         XzeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="t9a//lbd";
       spf=pass (google.com: domain of 3eliszwukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ELIsZwUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432aa51e6f1si719135e9.0.2024.11.07.04.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2024 04:26:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3eliszwukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-a9a04210851so62041266b.2
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2024 04:26:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWRbxG9Ox1jWEosn615EjV0m6FTX9GgMtqVyd/dp5Em197habD8Rv608h5U3PUkKat7B7mutIZZutQ=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:8fd5:be93:a8c0:7566])
 (user=elver job=sendgmr) by 2002:a17:906:d108:b0:a9a:1209:c4d with SMTP id
 a640c23a62f3a-a9de6007a5emr1152566b.9.1730982416079; Thu, 07 Nov 2024
 04:26:56 -0800 (PST)
Date: Thu,  7 Nov 2024 13:25:48 +0100
In-Reply-To: <20241107122648.2504368-1-elver@google.com>
Mime-Version: 1.0
References: <20241107122648.2504368-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.199.ga7371fff76-goog
Message-ID: <20241107122648.2504368-2-elver@google.com>
Subject: [PATCH v2 2/2] tracing: Remove pid in task_rename tracing output
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
 header.i=@google.com header.s=20230601 header.b="t9a//lbd";       spf=pass
 (google.com: domain of 3eliszwukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ELIsZwUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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
index 9202cb2524c4..ee202aafa9fd 100644
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
2.47.0.199.ga7371fff76-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107122648.2504368-2-elver%40google.com.
