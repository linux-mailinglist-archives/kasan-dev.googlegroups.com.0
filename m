Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTWLZSVQMGQEVXOAUOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DB2F80A540
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 15:18:56 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-286ef430ddfsf1726235a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 06:18:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702045134; cv=pass;
        d=google.com; s=arc-20160816;
        b=BwuDNkKt5d99nPyP9ZR+r3DQ1vcb+3LbmKx0xbKWfXFE+jsf2HEgZLf4ouDY6WZYrQ
         +kOSeBguItDLmAp9o4Rvj1o6AedGKhPSVnUzFr7XVW+YJaOhMakGCu0AzY5/kabS36rh
         kUbGwy8mmY2yuZW0y1tCoKWl0k0FAE53kKVEBA1tlWt0msPTiTjj52qGY9SJ79JqqNj4
         tn1wlQJC+fl1W+2A9trbfh8ZC8hB4j3B7G9uUk0RC6/054acGUoRc+55fvcfjPQ24p/j
         lE3FZ7o1Q+xlVKhSImnIZy3/qLwGz0hIXHJCAAcIdj8eeO3RBofUhR3wxB8QQ9Ig3Ijn
         exjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/LIDjktv/InqGrKXZQoIMqAp1KnDF4tYFHpv1JW5GoM=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=uz7S/fYW3iqsyFrf7Ijio3Yoodbx3tr9AeEs+V94N/q+vmCZyCI9vygYIRIjdjNrQ0
         1aM7RWlhF+LfPB3Rp2mEyu/gdVM1FHkE/3U6o+Vs05plpIcczqhMQtgkY11BvJTvU/dQ
         vGSU/bt66/xRpoZ9e4kXy3KkpRGSd/YztcgLvbxn+HO67JCPeuU0nXXgbi8QHbIte6Ni
         DbKLRz+u7KriuMhSKFPoFY6VkIhPzcO9DljjoHrYlJo5Rjk4i6fUD+tiCUoRRPGlOzBZ
         TpYIvWI1s78mCpmxBXsBw9xVSBoEosKXIJzP0GRHR9Rtg4OFmYGqltIVJxSJGp9AHNGn
         8T9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aZlJlHix;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702045134; x=1702649934; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/LIDjktv/InqGrKXZQoIMqAp1KnDF4tYFHpv1JW5GoM=;
        b=FwGzrrN1y4WsTFWYDBlC4z2brMzYwV/WFG3mJj/6SoayZ3wngcBY/1rDAlbnZPbNDl
         Sw+ubhK5bZFPE1S2WBzf1F8sogCm7pVzZJpZqxtFbx7sEH+X5GxTHJCh1ICkOOYih58Z
         EJIpOPho8yvDofT/xD6iOUG1AXoOVsBBIhLBD5j1TBzdfc8lCKDSMoXLP3GnK6t+qAd4
         WRt308Z9ZFaFvVBoDH+RcGDF2NtEVIBmYabj7MKAKBZ/iC3dukHOlcW7kKYqC2sTcS/9
         aT1l9M+OvoHs7XppsgV5cwKCg7wPN4anpD+dVM72njsOj3rDlCpokwz3y6kuiWRfqpbe
         B/YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702045134; x=1702649934;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/LIDjktv/InqGrKXZQoIMqAp1KnDF4tYFHpv1JW5GoM=;
        b=ZT9BUKyclYgWJsp6Ktj4zjre0osm/eKE5mibEJY87Hum2kOJC7wvVbQZQ4FTWcQ9TE
         XUrpAkzado4u0G+ffNoiHsweVy7N6S8W2jr70dWBrZulCNx1CQlT4az7F6GBtzoUu8ws
         0rU8vzsHar0kLCRXE4G6parPRpDje8Li3Yh4yUFnE1IFOkZ3aJ8XH+jBEaBg2MTEkDjQ
         bztNpmkMg/AQTTUAb3Q/a0y0sWj8s9iJdDgaft5OjRIVrOf6a7mCbj1rsb9XjsKrm4c8
         Jv16IFT/AYIrSc1nXc2HayWmVAnwdu5+1M3yBXxPCaYtswYJ9MzCUxjdbopSd6Pk+WmH
         VxJQ==
X-Gm-Message-State: AOJu0YzM9abT2kCk4bzMByr/6NvGTViPhCc4B+aOHzHHKyakeHFDM/1+
	FVAqehIfl0CsydO9F8MsHu4=
X-Google-Smtp-Source: AGHT+IH4/6psunK8AM3Uxudi8C4k0ZKqqH4ZgXGo0ppo3iEpkSEthOEjnJlySp1UgKHlNo7Ksq+qmw==
X-Received: by 2002:a17:90a:dac1:b0:286:6cc0:b92a with SMTP id g1-20020a17090adac100b002866cc0b92amr103920pjx.97.1702045134597;
        Fri, 08 Dec 2023 06:18:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2dc1:b0:285:8a5f:d96f with SMTP id
 q1-20020a17090a2dc100b002858a5fd96fls978659pjm.0.-pod-prod-02-us; Fri, 08 Dec
 2023 06:18:53 -0800 (PST)
X-Received: by 2002:a17:90b:3746:b0:286:bfa4:64a9 with SMTP id ne6-20020a17090b374600b00286bfa464a9mr107655pjb.84.1702045133596;
        Fri, 08 Dec 2023 06:18:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702045133; cv=none;
        d=google.com; s=arc-20160816;
        b=q3wQcWRk7GRMY5zPXT5oKZ0ACdaHl9/3c9wCgP8KcFjy0YkJzI9toEr1StbceO9tQ4
         ynf9VChq+v3A31n9Sx/8vcomifoP4/9hUD8n4I9X80NBsnRgUo12mU2Q6Pf7TZ0wmoIe
         Gbo5cTY9IJvK8zvc/UPIMzgyF52OJps+qI8YGloPbvQmTE1GtfkptzCbpOkbotKVvRio
         hJSJRhbs8+eHTZ7uEWN8lFBEPhKvaBphjH3Ai5eHQTYEUKNIwWrlLZC/kFUaNNknic54
         GCJZwJaU543rHpceNE6nW+pdN4u4KBZZ1SPlAUoB5jTFsdJsl2mNpyLJmMwuegBha5rB
         rgiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=b4aUU7dNjS/w6j2yOU1hBuNM/NL6fqAI1SOBM3IICMA=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=woA4ikUEyeinsf35NVuReJ433MhsAsbSnDL5iCYzCgirSP3bQiSVBjjpEOviv2DXYd
         u1UuDTe5+GaCLtkBZMPIsQRwZKjDC+DkocNIwnqD90k2Ve4BHstnezNxAEAgKcnZZn02
         XRK5pm3WeuPcIJjAX1t6bglqyTooO7Dtz7lY3h3EfDZ4uC8Xiqlqwh+YL3InneJInCh8
         bjlGVvfMJHDb39vWo9AKoc64h1mkueCWy/GqL0YLO6pD3LYA0fCvQXnnbbNYWLJH2Kyp
         EjQVgJMPssY+2blJWfDaG9o3n3xoN4LGsXev1cwsIUpatcf/eYVO4518l/AQIb+DnXpu
         83gA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aZlJlHix;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id z14-20020a17090acb0e00b0028655d6fd8esi152209pjt.2.2023.12.08.06.18.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 06:18:53 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-67a894ccb4eso11936556d6.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 06:18:53 -0800 (PST)
X-Received: by 2002:a05:6214:1023:b0:67a:be9a:e9df with SMTP id
 k3-20020a056214102300b0067abe9ae9dfmr23702qvr.17.1702045132939; Fri, 08 Dec
 2023 06:18:52 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-27-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-27-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 15:18:16 +0100
Message-ID: <CAG_fn=UBaF8SnvJ4t4wbBZKbNEBWRyGBY=FA+CTB+k2+pa2qEw@mail.gmail.com>
Subject: Re: [PATCH v2 26/33] s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
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
 header.i=@google.com header.s=20230601 header.b=aZlJlHix;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as
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
> s390 uses assembly code to initialize ftrace_regs and call
> kprobe_ftrace_handler(). Therefore, from the KMSAN's point of view,
> ftrace_regs is poisoned on kprobe_ftrace_handler() entry. This causes
> KMSAN warnings when running the ftrace testsuite.
>
> Fix by trusting the assembly code and always unpoisoning ftrace_regs in
> kprobe_ftrace_handler().
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUBaF8SnvJ4t4wbBZKbNEBWRyGBY%3DFA%2BCTB%2Bk2%2Bpa2qEw%40m=
ail.gmail.com.
