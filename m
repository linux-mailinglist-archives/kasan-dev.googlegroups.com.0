Return-Path: <kasan-dev+bncBCU73AEHRQBBB7FYVSZQMGQEMSNGY5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 689BC90782D
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 18:21:18 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5b97a20705dsf777001eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 09:21:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718295677; cv=pass;
        d=google.com; s=arc-20160816;
        b=rCWUIT7Tdxj6MfSuXiP0LkQtiWr0nhrncvlUHt3p2DyAMEQzpQvZ/slfW8h8wj6vQB
         3bZrGs7Z6heDCiqS9SmBK8+e3fjTd1CuiMB3oSrjVIE9G3py/3gbc1zW/HywnGzDP2J/
         xFOy0WdlodpSErvtNl+Wz9WyCiPMFZG7XYlEJ9kTK5/hT16ImMqHy4u6QyjJ/v9NSPKl
         9muAq+GVh6k6iIK9wtXXkNMofk6sY4vA7OEiI1ZbaF75vie8dpGStqMPmNeYwuGjVJhn
         O34JojsB9Itjer+nvdXkgbOUFG9TsfGOxQ7fkJux43aBheob8ek2g/4IyZZ5S2qTK+10
         SFDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=OxWkAwL29j0CKfuezUbVoCzSV9xxm0HTGeA+Fkbsm9M=;
        fh=wGJsrHsspEJd7cdY2htzprfwhSs3CzOhTUkGU4ZxWx4=;
        b=QazYZUA6LHtqM1F21/rVwsdeCZRpL8PuKEOL1VwRh6YS3MwTRIaXj1RjxuaLl0hXEx
         jYFCfWfVKhzRWNd7Ba8OBkwgPcJD3/LflvYdcuDfDaSahdlVPV+1KKaNWHcqHkUkbyAz
         OfYrP7UBUoPUN4WPkggLAwJ9dJUG7rBAKObjsDmqm6mLHGidOPml/c9+v6smR6m0H0Wa
         XohAWGmX0r8QLFISxkw9o+L/PmWGq7p7mojv51tDgI76S96OP5e62jfMi8ZrBIdwoYDg
         zBj3znplO/tXMcfjqnti/isFl0M0v2XaBOq0UCaaXueX83RPytR5fQ68evTBQGnY+8p/
         /hKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=yskb=np=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=ySKb=NP=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718295677; x=1718900477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OxWkAwL29j0CKfuezUbVoCzSV9xxm0HTGeA+Fkbsm9M=;
        b=YH0SqC+NCAxm9zsUYi2lzMV8fXB8ecDCuNoF0BoB6AGZ2VWxrrm79fZBLwEzEgoH0W
         bp8+mx+WKBX+lhzPTwg2kPNsc4ETdF5h8V9BuPTG7lqW0PF1hzQodc0OPlxNQBNUwxzs
         egOFN77HsYa+5oytMMzzZBSmuWyhs67wlBAebSX2UHIhEfl287PnSuo0xAVa2Fr587ct
         S3Hl7/Lpg1NBXCPivjstrB0Rk2Hz38zKj+bRY33PfhTPIzhMgsFcv7zFnSqaZFaoVtvN
         PsD6G/5qr6U4gCwAIei2IMJ6XgriYFaAlZItK5Y9+lqqFRD9HTm+PTgA6lNFqSN5OUgI
         R+Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718295677; x=1718900477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OxWkAwL29j0CKfuezUbVoCzSV9xxm0HTGeA+Fkbsm9M=;
        b=j8DkUhvS/PDnzW9cDzR3ODVgA8dbqm04xSbbVZQIkwHOaFxytD3noMFdEEWXz9YNm6
         gVOWg7ys/sMLgc62+LaD2GIQBzTl8dinwD8djbpc66BTFKmPRZQVIA8Tyu27qMFMKifH
         4sY5G8iZqjPVTumBmTwNDRBmBwHvdtaqHU2Hv6X5aMcgBOLRLuYu4BoAKjEBbBEQ6xRA
         fpc+4DoYOpbqQQhp94woL0EXOfwlr4/WZiDZOcScrgx6KbaFcfEqiy+EfmIarZhQKk7c
         mka4KJ+qHMXoHik9+k6L/YiRJa+GKbkf4oGIsZpLOKHoSKrUej3+alDb2dtF2Q7RMo5G
         OFOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbPWJIn3zq2PQXiQqIVD2N3uHB4suOWHB2l5BCehWAqIuElan3SL6D2o2suIba0tqP2h9NX4ZjRmmJhPX21RLsnCI0psdTYw==
X-Gm-Message-State: AOJu0YwsbLpnSwoMRLODRXLBuvZQLQ1cwSJtyLnHVU/b+PV0/hNi5E+R
	/BqS4obtW5uHjfSVgKbZIC4t1pgTEUNO0iRH9PPvN/DS1mubeuMI
X-Google-Smtp-Source: AGHT+IEr7X1kl0QtMNxLX40HrHjkVpdhrzDgvi7oORBgVpVp8YmLUO7cuxItVQNxrkeRgBfndXcoow==
X-Received: by 2002:a05:6820:1ad3:b0:5bb:36dc:411b with SMTP id 006d021491bc7-5bdadc5549fmr128105eaf.6.1718295676851;
        Thu, 13 Jun 2024 09:21:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:af0a:0:b0:5ba:a73a:6de1 with SMTP id 006d021491bc7-5bcbd935466ls1070976eaf.0.-pod-prod-07-us;
 Thu, 13 Jun 2024 09:21:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTswCfTPiTNXON96w6qpzpw52xFiO+Yon6P24ABxuLhsWVk30hK0TNb2l+m/300b95qNNh3OJwuxB5ZBsmCpa5JWu2reKljGTpcw==
X-Received: by 2002:a9d:6397:0:b0:6fa:ea5:d32f with SMTP id 46e09a7af769-6fb93172a78mr302232a34.0.1718295675681;
        Thu, 13 Jun 2024 09:21:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718295675; cv=none;
        d=google.com; s=arc-20160816;
        b=sSL5ESKmfFW3jpA1eQsebPIFRqogb8K8uyRcOQhlfE9qx1rk8Mle1nX7uAjCwfHZit
         Bx/MpaddefpS3FnnF2h5LHvNy6HGl9HK4Hezv9UpO5+RjApBEJ/xl2b2GZlI9LiWejCe
         GygvXjuD3iEuo19zS+ucLlRfsrsGi2uuKfFT/H7y/0fJtmqM0kZZPyyfXe/npZin0v2s
         +wWCJ00H78rbpaSsBYjG5ztZEJnGfisHIDyOi9oUpY6kWSBMbG0UZldFLsf1T+kkx/0H
         xz9r+gwGLQ31qMPLWAeJZuPDpl3Cn0tF7zzToGOohJFcfB5tqhbOGKn0UNSmOu6P0dwW
         OTxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=Pk8TjR44mVtu2x8GczkKUnp/iceWRQZ53zM5FWeztZI=;
        fh=KkKQYtzz6I3Fheaqbs3DScUynHU4Y0XBjEVlwCNbTnM=;
        b=VQSU8wkWjlz1aNZ3kMMPRieeMWrYR6JsBasuaD54451nqyhXZpozIKK5ExH+jMiZKG
         sLnytxXc2m211vBFmBzYbwjAHo7ed5a/mGsVp5LVAQyAJS5l63slpO6ZgoRyry5sbtqT
         1KECtg1qSqil6n4crAGPt1cpZw4okC1a4XfplX06YLN4cC/+iSKpd8L6RzndxJ54LFt6
         QXOokDfcfskYVj45qdYM7+pzPMe2/kchzov+FZomKpWSkhs5y2Sh689KfK6M45EaQknP
         YY41Ot2jZIi1wVFIMweqAuc08RlNVNCjqHcnWt4qFuTsO3wQwINoflMx4HLz36MpLeHi
         ZZAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=yskb=np=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=ySKb=NP=goodmis.org=rostedt@kernel.org"
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-6fb5ba85bbcsi81411a34.5.2024.06.13.09.21.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Jun 2024 09:21:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yskb=np=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 9157BCE270B;
	Thu, 13 Jun 2024 16:21:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BA525C32786;
	Thu, 13 Jun 2024 16:21:08 +0000 (UTC)
Date: Thu, 13 Jun 2024 12:21:07 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Alexander Potapenko
 <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, Christoph
 Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko
 Carstens <hca@linux.ibm.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco
 Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, Pekka
 Enberg <penberg@kernel.org>, Vasily Gorbik <gor@linux.ibm.com>, Vlastimil
 Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-s390@vger.kernel.org,
 linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle
 <svens@linux.ibm.com>
Subject: Re: [PATCH v4 01/35] ftrace: Unpoison ftrace_regs in
 ftrace_ops_list_func()
Message-ID: <20240613122107.6e9299eb@rorschach.local.home>
In-Reply-To: <20240613153924.961511-2-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
	<20240613153924.961511-2-iii@linux.ibm.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=yskb=np=goodmis.org=rostedt@kernel.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=ySKb=NP=goodmis.org=rostedt@kernel.org"
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

On Thu, 13 Jun 2024 17:34:03 +0200
Ilya Leoshkevich <iii@linux.ibm.com> wrote:

> Architectures use assembly code to initialize ftrace_regs and call
> ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
> ftrace_regs is poisoned on ftrace_ops_list_func entry(). This causes
> KMSAN warnings when running the ftrace testsuite.
> 
> Fix by trusting the architecture-specific assembly code and always
> unpoisoning ftrace_regs in ftrace_ops_list_func.
> 
> The issue was not encountered on x86_64 so far only by accident:
> assembly-allocated ftrace_regs was overlapping a stale partially
> unpoisoned stack frame. Poisoning stack frames before returns [1]
> makes the issue appear on x86_64 as well.
> 
> [1] https://github.com/iii-i/llvm-project/commits/msan-poison-allocas-before-returning-2024-06-12/
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---

Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>

-- Steve

>  kernel/trace/ftrace.c | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/kernel/trace/ftrace.c b/kernel/trace/ftrace.c
> index 65208d3b5ed9..c35ad4362d71 100644
> --- a/kernel/trace/ftrace.c
> +++ b/kernel/trace/ftrace.c
> @@ -7407,6 +7407,7 @@ __ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
>  void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
>  			       struct ftrace_ops *op, struct ftrace_regs *fregs)
>  {
> +	kmsan_unpoison_memory(fregs, sizeof(*fregs));
>  	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
>  }
>  #else

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613122107.6e9299eb%40rorschach.local.home.
