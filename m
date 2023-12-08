Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU6KZSVQMGQEBVFCUCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BCF280A539
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 15:16:53 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-67a940dcd1asf26525376d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 06:16:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702045012; cv=pass;
        d=google.com; s=arc-20160816;
        b=G/pf/L24rwPV5RBTsb/0llobDswRnI+9jWga+LD5A7R5Ya5Vb/7//acu97M+1SQsYd
         R0nTJ51GkYriXBMZHJN/pNPzJY01A68qfoNBFk6aAIkOze/PwGTMru4cdGAvx3EYUOoR
         yB8KfPuZ+CjpSkRBNIPFyCqninGJM+LDZjJm0klUnV4QmmE8BwobRkCeETnn0dLVMFMh
         qUocDu1VGXdO5pwkWdwJxze6FsUF70/DXTCAVtdczV0OpOsZm5QpI4VDJCp/HM7lNe2Z
         hmIljMRGHsIDm9gJ9cUn8DiYwibJO7XckvYjErYNeMJJke/+HegxLtH6HJ5Lhhh0OGn3
         rx3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7OOx6XeDAkHcR/R1Vl7mfD4UAwfC/9iGGbzuTr5v/6w=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=X/67ORPRXq+J9PJcPX6nYviY9jMvnOKCKrYVZfE76DC2njQeUsQkZoiAduNQV7Nk9w
         YP/kzUf+ua7b31q8q2BMQL1yajwxK/ZYFxyagMcdELpVzJhxN3sL1h3Mvt7HaD3FDcWl
         ZFbgnGFCaiYOsXaIMbEZsWbgAbG6iCfAjvGl8ZYJo/qrYwK98TV7yxsSU8PKbTMHRwlZ
         AowQsBr675IwEWO84vgcTWCGpDGG5VebdE8YreEKk9nJuiqkRUncqmN9dwL3O265ubDV
         4rfNSKr5FNDOD2IObjWurZVE01daVt67Vq+2b/U+JONjMYnAXZ8oSMVLuPsvvYAqgPEN
         e1Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C3rucscG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702045012; x=1702649812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7OOx6XeDAkHcR/R1Vl7mfD4UAwfC/9iGGbzuTr5v/6w=;
        b=gD/2H74nkaT3IHxsIrIHirCYyOPNkA9WhdbiiQCV+b77v4GTEyVc9/YIgfn8DRlvGW
         DSPIWeYo3SyvhgTBbRbk8LSQV82AGZNvQRcibyEB4yJObLMxDEUGOZwmobw98Bt5Iakd
         KLiil6dI/ScdynG5gP3syZqIcm1EWi5eIQsaIC21YOtyLhpZkniiFOyvi6jDXc26/fWn
         duoX0BW+VMrF/NvedHtCNKkRUWFIqiwFRrKG6PmPkzuYypMEH9KvlDFkL8UjtsuN+zVX
         f7ckXYjCcymNuw5Ge5l09D9be87AXovnA2P11POLd7j36xhEqGp4P9ATUivZBlcd1LBB
         y9uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702045012; x=1702649812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7OOx6XeDAkHcR/R1Vl7mfD4UAwfC/9iGGbzuTr5v/6w=;
        b=PJZaOLq5IYw6/OKy3JtYalJdmspa57GeWdYNkO+XCMxQSU/WvatVqdneB5hLQRIjmT
         WZvLYZaCMtBlhlhgjA5O9rRWM2v2WgKJa8ojeO3D+RoeRbooKeteX36jUwibc41QraD+
         lA8k9NXUV1kGOvlYexVQejgtboJ8RpHkKtqBtPfbJUXWgjCGVh1tAeJ0TVJK+eJSuyct
         ODMR8aC7Yuhm96mphEl3Rvmv+fKnS+r+DTJXeFy1kMolGhQH1C67ECT+gwqdnwTm9lSH
         GUP2k/Ws1eFD/9Od6Q4quZzOpzkTXNrmSDIa2PrS6WEUUCFSlHpm+pikqKFwS4O0u1cI
         wQEA==
X-Gm-Message-State: AOJu0YzZ4euzkvaCljvrG01W2pTGRvyemwljmCvrV3TzP+mxz5dTBNeX
	HiKCT3Vb7IJFI8TcT7vVQaI=
X-Google-Smtp-Source: AGHT+IFTjE5Zw/1oLIVRcDbpFLPqVbwnjoa/9pxFuVP2tmCYCrV+bfbqp5tY0qon3gZ91olz+woWcA==
X-Received: by 2002:a05:6214:401c:b0:67a:a721:830a with SMTP id kd28-20020a056214401c00b0067aa721830amr4084829qvb.100.1702045011950;
        Fri, 08 Dec 2023 06:16:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1924:b0:67a:1a4b:e43e with SMTP id
 es4-20020a056214192400b0067a1a4be43els1985199qvb.0.-pod-prod-02-us; Fri, 08
 Dec 2023 06:16:51 -0800 (PST)
X-Received: by 2002:ad4:5149:0:b0:67a:396a:8906 with SMTP id g9-20020ad45149000000b0067a396a8906mr31707qvq.0.1702045011211;
        Fri, 08 Dec 2023 06:16:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702045011; cv=none;
        d=google.com; s=arc-20160816;
        b=eziTXQ3k7TgLgqyEouLuvDULaT4kbZ4AnfEkUoUQpLmCjniSvmzWZukXEW7MJWe3+F
         HD4UUjK5Fgb/c78R1CT9A4E5ltGmDZcax0n2opq1fyIg2TzbiotTu405QD55GhqaO+Qz
         LLFAxWxNkrPADADh0xKogaUKwRfE3T5zuWxJwo+Yki9O39KHU6BwLUix20xqHVANAAzA
         JxaIt5naDayEkORy5XccaQxbyVubqgZwbQzV9Jp12KVbkvYiYcNaXFPBE6X4vdA8hC65
         iAFe/l3/SPzy6Plm92HUhbztJa7dzEKgDWMaLipOeNjwyUl5OKRz2nb0EaCbAC3Vg+SF
         DvWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/0j5IioITwyG/4BP+tqSeHc4KXtugt22zIQNy6+j6UA=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=X7vsZjyGca13bhBSFrfB1Ks3pLs3xY2QbQb+xPFPPCQqEQyB8fFNmxaWZvCC9m8uHH
         XQSraRRNyegZZdQsm3GtbNiLDcxm2fnz4q4XC+MqipTD7oQbYwlheSe8pEouFRceOxxt
         sizTdhMEtznDo2TIZGp4NAyIS019Dp4i/Bo7+UhX6IwS2uwdlhUXGtQEVFvY4Cp1FkRn
         pLdiX/WFpDUS95hWFJdjcf7m8gAupNi8eRMtT971KCgWHtDZl/50hMviFglDdeAauJYi
         dDFExywtvRz76WhEMoKp1PxgLGwwstXZ8dbaC8AdhHUloXtG1U+l3h2Grd5iirNGWnvt
         UlfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C3rucscG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id n6-20020a0cec46000000b0067abc7d2c36si214438qvq.0.2023.12.08.06.16.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 06:16:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 6a1803df08f44-67a894ccb4eso11926326d6.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 06:16:51 -0800 (PST)
X-Received: by 2002:a05:6214:4a50:b0:67a:a721:8309 with SMTP id
 ph16-20020a0562144a5000b0067aa7218309mr3763142qvb.99.1702045010694; Fri, 08
 Dec 2023 06:16:50 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-2-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-2-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 15:16:10 +0100
Message-ID: <CAG_fn=WHf0t=-OJL0031D+X7cX_D25G7TG0TqROsT34QcEnqsw@mail.gmail.com>
Subject: Re: [PATCH v2 01/33] ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=C3rucscG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> Architectures use assembly code to initialize ftrace_regs and call
> ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
> ftrace_regs is poisoned on ftrace_ops_list_func entry(). This causes
> KMSAN warnings when running the ftrace testsuite.

I couldn't reproduce these warnings on x86, hope you really need this
change on s390 :)

> Fix by trusting the architecture-specific assembly code and always
> unpoisoning ftrace_regs in ftrace_ops_list_func.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWHf0t%3D-OJL0031D%2BX7cX_D25G7TG0TqROsT34QcEnqsw%40mail.=
gmail.com.
