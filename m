Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSNS26VAMGQENHFH3XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 44A997EDD29
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 09:56:43 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-da04776a869sf754626276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 00:56:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700125002; cv=pass;
        d=google.com; s=arc-20160816;
        b=EaebLMY4ZZkIWus3WOEVc/IaB11iGQTwwPqmNF/ASHLp7x00aUi2VaYF1iwqkwxwJR
         ei7uRQnZLdswfjOwhgKPlIMnvgamO/tNZioDWYni4BjYLRNc4BvNw7nhuLn6geFrA7of
         a7Vb4ejcYf8mjOnfXci3y8FLUVcZQfvxmFEDzUcdrO/gL4O8ZjJW1Vx++wFaIF7YCAT2
         5lRWHiwZSm6UA8fxGnYcmsuU1TCV+o1fJS1GcDpVK50psarhZSQY/Mks8s7RZIt7cWMn
         CohODu4fKsmu7Izh8B7C7K7UgpThLrnhFMGX6bjmcIbx3fNLi2HBJ+uYDnYxdKqXf0pv
         3aXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RQA4bz87XiaUOrnoHShtrvtjj7UTL7XN6pzGbSrKAAE=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=PDLfwm+HfcGV6d4L0Re6zvYtnPUzp+ayvEeJM73em0HYeWp3j42rhfRTEwH5382coQ
         D5K1d7Aaw7CUsw8Xd0Hf0or4pD4wDzIhRog8P+FOGeTkY4Pq0KRr3lUzcwBRbgMfkb4f
         x6415P2P9TfzdrCb7hYnS0eqJaphSSWhYP1BQN3VdrrLFDw3TB79BnJWYP/W4YYgUUoT
         7zLwMHwwZPA+tv2P1lGBujz9e0g5uWVsDwet9zUgWAuFAVFU/4WOsu59KDosXTlVzGuT
         OwFseSwGN3HaNWVT9DrTbWbh7WPjlWsNk3jvfsVBiDqI+nmbIYXiVWEji30HvxX50ptK
         lI0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UbFPVgDs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700125002; x=1700729802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RQA4bz87XiaUOrnoHShtrvtjj7UTL7XN6pzGbSrKAAE=;
        b=LPJh21K96M31Ur4vgyPZEhwnlVKIBBTxqNw2+HHcshxNq8D2YGP2lBkudemKLzpgCA
         kVEJ/Lk1mSe3yDY7+vaDeSvBTpUXKI03bsaVCFmUC8sV8n6RFzLAIvCgvn9PlYy2W7gG
         QBV3JZbrXrgHQY0+E3li+WHRXbu29rqSIObS04RX6m4ydKwwkE0jdFlRaRBCe/k22+mp
         ezRqQQuZF1tUqS3fEJvBIQbKF0sU0U/R2XcYkJfNGKrHfuK5ASWSPcMssBAmFc5350an
         GAjfUDEnAj6QC6s9vfB+dpHL5ft/5xI+JBLcCnXFgoOUv0qaFcxJdaZGaoQbBT0zf6dF
         ETtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700125002; x=1700729802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RQA4bz87XiaUOrnoHShtrvtjj7UTL7XN6pzGbSrKAAE=;
        b=MrO2vNgguDNTh5kvSAAPoTclZjIjQNJaQy+8X0jJO5Kg/1ArrCBIp+l+NTPwqE+iNK
         MMQ1pSflmg+mUpsxjZ2Em4RrqmCRyaItsHJMdiRonuQxfSebfxJVjATwKjF0LMBgXRl8
         bXqR+LGItiNXu7Cc4xW//iXFfEcgR3th3wkgZBUU3EELAnW/zuF/QDIDKUCuldZnujUn
         sQRPL35dtQYRRlsUGn1g3rNUBjiGzr5hvQmhsbnlfc8GQFC8zDuHY+QizNUir/jb3mhX
         6UP9f+/BmXWAL6q4vSthZgehlfZOGBbbVNazZmWrjkd8839x0Xhoz8gwmmxRV9gPpBYo
         LfOA==
X-Gm-Message-State: AOJu0Yxa1RiJB+/MyNDQp9OKvYzZI5FsA40R3a4xX9fJNIenBr/rfYuP
	8dUws2A9bMYARfE3/SQF7X4=
X-Google-Smtp-Source: AGHT+IE9a3ylBR9jN+ryub/jHLqcXtTkMOdAsdNBKjP37i5mJ9F6Lj4JZLdWEzKOiTdXpitt8cZKqA==
X-Received: by 2002:a25:2487:0:b0:d9c:cc27:cc4a with SMTP id k129-20020a252487000000b00d9ccc27cc4amr11910453ybk.32.1700125001870;
        Thu, 16 Nov 2023 00:56:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d651:0:b0:daf:5edf:8c69 with SMTP id n78-20020a25d651000000b00daf5edf8c69ls96777ybg.0.-pod-prod-03-us;
 Thu, 16 Nov 2023 00:56:41 -0800 (PST)
X-Received: by 2002:a25:37c7:0:b0:d9a:6b46:f49d with SMTP id e190-20020a2537c7000000b00d9a6b46f49dmr11913347yba.59.1700125000944;
        Thu, 16 Nov 2023 00:56:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700125000; cv=none;
        d=google.com; s=arc-20160816;
        b=KtX/9lLaxEjs3CuAUrVXaQhgmY3ZZY/at7sMHoIl3CjW0SJc4CJEmXMNu+ViSsVjHm
         nb9LSpEF6qfhodlmI3RrnwiQDVu34UUvmn50VrJhDB2fyZuft7WRJeYiidhsmpugzVbO
         ZoJqse2y01+z/o96lTEfU3Kp70bOyLVfBnvPnfDu3WswqBbdTKB4ak9SWksxLzfNZLA1
         veQQZd1BO8lNc93UPDDHWAbwwh9/JX+D84V9Nh4/1g9op4MxqSF4NXjKpMm/tUSfFk1P
         NpKCu+gCeDNy2d4UHhhp5D29HxvvXjNWIqbXkmvL91832AUmIRM4i3kmBg7hoMEhXtgl
         nKIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0H8tt9dZT0qWTNb8kikU8kJP6qFA036d+J9DtuTzo40=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=uE3XU1s4KzDmWJ8PDGWehMtlkYFwj5zbrIihWaen5t2ecH4bmInzUiOBSGHUZ9TzrM
         yVNNBXDFBB9XmYrDdwBVg7yO3PmRqnC5OnpnBfSzHdWOcfFWcbu2RnAnQYembGDDM2l2
         TGVhAMxvtgcam1+0oxKGuSMtbVnAueNNpWG5wnfSugzq9nYUs/Pt0BXZT9sJsxp39Y4F
         QvwU8xhbYHeKAm09v9XyS1X/JiYnM3jcKF9Mvn1ta7SPpR/U3xQf10xFlROGBEOPzwL3
         IyUfxoIr12djpljvjWrM94sikZgziEfYx6SkE5Rr5Pkv+SFfBkqbS3L55kQckqbry0Pj
         spwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UbFPVgDs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id s17-20020ad45251000000b0065b087b16ffsi893461qvq.6.2023.11.16.00.56.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 00:56:40 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 3f1490d57ef6-daead9cde1eso521212276.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 00:56:40 -0800 (PST)
X-Received: by 2002:a25:b18e:0:b0:d9c:a3b8:f39d with SMTP id
 h14-20020a25b18e000000b00d9ca3b8f39dmr13846249ybj.65.1700125000447; Thu, 16
 Nov 2023 00:56:40 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-13-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-13-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 09:56:04 +0100
Message-ID: <CAG_fn=XVJNZLtHj2n3DP5ETBzgoUZL0jQFX7uw4z9Pj2vGbUPw@mail.gmail.com>
Subject: Re: [PATCH 12/32] kmsan: Allow disabling KMSAN checks for the current task
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UbFPVgDs;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Like for KASAN, it's useful to temporarily disable KMSAN checks around,
> e.g., redzone accesses.

This example is incorrect, because KMSAN does not have redzones.
You are calling these functions from "mm: slub: Let KMSAN access
metadata", which mentiones redzones in kfree(), but the description is
still somewhat unclear.
Can you provide more insight about what is going on? Maybe we can fix
those accesses instead of disabling KMSAN?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXVJNZLtHj2n3DP5ETBzgoUZL0jQFX7uw4z9Pj2vGbUPw%40mail.gmai=
l.com.
