Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2G2RGZAMGQEMSS2DGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F4188C47C6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 21:43:38 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-635f5006685sf3175134a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 12:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715629417; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jl4jDGdNVR/HNPRTlzttsLtrrP6PtYzW/h83zHUNL7GwV5FJxbjGD+2YOyYlZuhkki
         La2SoEDtDE/BIgs2G2EXHuo5u6wWzzieseXpFMLCyVQL0ILonmFYY0ACTZEPmbpvu7ve
         NFAIh0N2a5e+J2maFBQjT2wW/H6bw8nGwyy8LLBweJCBHF0Aa8rzxOO2u/K7Q58tLv5Y
         0x2BRbnmqiJrgXFq9Un42bNFBttKY2jnQLyGPum+8i2i7FLeknB4X6/XbPSo6BRQvaTw
         YYKRIyzufw2bsN/qtgERDdxzVgC97DSyQW4ypmn+Bw8QAB4Z651VPBpaqx6AG+yTYckN
         nZfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g7+wVyFuFkui21p6uqzMuuo0yrcdb0roni111Cs7vhQ=;
        fh=RDx5bscJ90hfUXcCw/meJ/JmEkmdAR/lMjUEH8+YwDc=;
        b=HRxLIn2QMPKRSpsVoJ6NZATQAEuGtf5OGMx76Fx4t1UGfrwdT82Qto+dPNGQxRJEgR
         JNYEGny8BStfVmNs8txyROzEclEXKFjMVTsxY0wNA+nhzM16vcI7E2tLCx22jgaZIRgE
         Yy/ukCAVSObRZ7yOm+olq2zH4icsJqsNHsL6vMfL1+H7Su49BdLzE6IrziV5f4wxGXRb
         RqtntnagVtv5kHnPLtP6ntybcKMolv0/uPZ7rJUCK6/T162Fydfq4I76byWIt3rts8Ma
         mtZ+WWiVd+34zM/OZ6Lz5Mlq5a2GnLpcs4KwL13FSOEcoKJytsnp1RKpA/pxW2JJlqCc
         vZ8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3ya9Tdmr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715629417; x=1716234217; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g7+wVyFuFkui21p6uqzMuuo0yrcdb0roni111Cs7vhQ=;
        b=bIOZiCn8LZqWyJn4+FIloeJX608o8BqqGb0TbxR64ASilKsl7cP2X7YWFFDGWvwQfj
         HB1aVpqdS0h7zdV1oVmqFCTqqYcplN9cRLj9tQFe3ALJQZ+/EbjIC0hTddaKCgGTgHNp
         IUUVaJLHbMASTue5Xre8kuwvWdVhr1YPYrIPZXr1QNJ0VhsiLUbdxxfbD/YFjM0G1lfC
         jnjR/5uyAGD/u/xdpCj4PXMqyMLdZDzTov3sCjwtnsvcx3B72Sr/BGRhLYR7XAeEzksQ
         Ks6FkFNnjGkWyB/lcmEaYaUdC6ReMAzBviLyjv7M1JJNWoEPhNdipW/KqxNOKHqSw2lX
         AkiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715629417; x=1716234217;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g7+wVyFuFkui21p6uqzMuuo0yrcdb0roni111Cs7vhQ=;
        b=u7HZu4fiiI4FVQ6FZ4FKw2M6VrVvZwYBSUPSqtzZWu3XV5AMX2IjPO9wYk/8UDbVbY
         hQBa2NZT728YY0WmtTf/eJHDkbcqPJ4l/4VysvJsJW99J0QAWoCA5r43WZNImd5gP9RI
         YFniD0+qQkS/ckqDQavVZZZ0WCGUZjQeUJ+vC0+dTVlL/j3EPL8Z3aE3DwcpS1YUugFt
         bD2tg/KOepK6aywMtceV8TBZ9wzE8Wa+CpVglEq4twDQZl1mNO06TlVjS7k/3tjf4fOQ
         GxKyLDs3t4u1POaeARk/toVIuda6vCgbHc23GE7acuKKUNp3yZ+/YewtCyKg3s6/e510
         bdfw==
X-Forwarded-Encrypted: i=2; AJvYcCWoWkDQHHxN+wV5QQhy5bok8nnUrXBEeqGQYsEmfIEkInaurWDpWj1lS0BtkVeFJDYhS9iqixqKzlSCpQan7E+IS2QJRS5lEw==
X-Gm-Message-State: AOJu0YzEA3EBI6yCQGdfaXlDh0IKTpuH8kf9Zz2W6vZcSRxH/Ccm2uKu
	dSMkr02/+pGZiYDYgQiS1o39/B0w8+vWqseZe7G7n6QtOY9+pHaC
X-Google-Smtp-Source: AGHT+IGwB8+tsvHyC8XJLwkvqRH5oSUNkkyUOjT7FZs9xZ38DHg7MPZ/oLnTEwNpAgnw+JV9JAmSpw==
X-Received: by 2002:a17:903:22c9:b0:1dd:878d:9dca with SMTP id d9443c01a7336-1ef4404a347mr144335775ad.48.1715629416427;
        Mon, 13 May 2024 12:43:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22c3:b0:1e5:1108:afca with SMTP id
 d9443c01a7336-1eefe786920ls30532885ad.1.-pod-prod-03-us; Mon, 13 May 2024
 12:43:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdx79NtHYZptrFd0CsvAxHk7pspl+deuAfRsICfhsyUfkuzkSRYz+Cgwa5ZXZW/4WFgcHYnhGaJEKgN8RAZKFnKTH/Ta1HBmn6gg==
X-Received: by 2002:a17:903:183:b0:1e0:c37d:cfcb with SMTP id d9443c01a7336-1ef4404a1c4mr155079335ad.49.1715629415022;
        Mon, 13 May 2024 12:43:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715629415; cv=none;
        d=google.com; s=arc-20160816;
        b=EOtDBq0yFVRf2K2RrLQTyc8/rDdVI6oPcSeiJHCw60eDnwjhL19g8A4FYkPFaH8H+N
         ZI4o9+8RhRvsFX68vBnIgedN97zk+eMdSdZjL8hbd2FefpOBsTi597tAHCmlLziiHApx
         qIsRkIat9+apKLMHsqksrESI914zLnUBpyuxMmAoC9aTE8LFfLNw2lgtFhNWEDePhxv2
         gczpQ9Em8qYwJBo6DNuhGFibo7byhrP1lDxoR5OqKFgY7FlebMa4p2zkETE4uDJtzDLk
         c6b3Nh3eN2OF2GfnkWTbLKs6hCfcI8VCi4VYoEm2miH22WGiajX45iKxdgdVrzGOo9j1
         l6rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OB7Egrg/OovXXPL7eaghFwI4pOy73lAunaMZLiaT7nQ=;
        fh=9olZNRxZNPamsn6xEE45DGRh+HwsnF19nYZtTid9gqg=;
        b=CdcGDtFWhW6XxxHmePrkzEiA5EAL3vpOp/JfdrR3vXexRtfsN6Bt9rUQP9L5F+kksP
         adV8kRXaV4uLlPPTJp6/zhY/Dd4fvdm22naeNzl1NKnqLRHWFSzyRZ9brGLIaRumMZ33
         gUNY5cQSAT9gfnVkhirV+tY+ODl5BsTl1hwRxd4FtCv+jtMxsLFTjBT/VrWFPIu0XnCk
         fGsWwgQEmT7YPS8vy3cM7umeh3XzHKifBbp4HTWupsnyfilGjgDd90Pu9eNSC98SNb8U
         iqMn7jcc9C5eeaJrdfbLrTciBIEXUre6U9JRnXBV0Z5djni9MiCAtw0dJ1hYlj3UtoPp
         Tmvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3ya9Tdmr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1ef0bf2def4si5166915ad.8.2024.05.13.12.43.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 May 2024 12:43:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id a1e0cc1a2514c-7f16ec9798cso1128170241.3
        for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 12:43:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZLW9CQJcbuncAoUVIvJgv5Fs/0MZpYlbPdIdxpwc4JaeBotow7Ab/5T9YMpgSdrBB+y1iCI5wMPdPV8dTMil8LXK9ev4BC1r1Gw==
X-Received: by 2002:a05:6102:38cd:b0:47e:f8c0:c453 with SMTP id
 ada2fe7eead31-48077e187e8mr8525537137.19.1715629413783; Mon, 13 May 2024
 12:43:33 -0700 (PDT)
MIME-Version: 1.0
References: <20240513-mm-md-v1-0-8c20e7d26842@quicinc.com> <20240513-mm-md-v1-3-8c20e7d26842@quicinc.com>
In-Reply-To: <20240513-mm-md-v1-3-8c20e7d26842@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 May 2024 21:42:55 +0200
Message-ID: <CANpmjNOAJOsa3S5K2kdMQo+rS8WJpsT3Rew96VMfmftC_naRNQ@mail.gmail.com>
Subject: Re: [PATCH 3/4] mm/kfence: add MODULE_DESCRIPTION()
To: Jeff Johnson <quic_jjohnson@quicinc.com>
Cc: Miaohe Lin <linmiaohe@huawei.com>, Naoya Horiguchi <nao.horiguchi@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Minchan Kim <minchan@kernel.org>, 
	Sergey Senozhatsky <senozhatsky@chromium.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3ya9Tdmr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, 13 May 2024 at 21:38, Jeff Johnson <quic_jjohnson@quicinc.com> wrote:
>
> Fix the 'make W=1' warning:
>
> WARNING: modpost: missing MODULE_DESCRIPTION() in mm/kfence/kfence_test.o
>
> Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
> ---
>  mm/kfence/kfence_test.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 95b2b84c296d..00fd17285285 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -852,3 +852,4 @@ kunit_test_suites(&kfence_test_suite);
>
>  MODULE_LICENSE("GPL v2");
>  MODULE_AUTHOR("Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>");
> +MODULE_DESCRIPTION("kfence unit test suite");

Reviewed-by: Marco Elver <elver@google.com>

I guess this warning has been there since the beginning, we just never
compiled this module with W=1.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOAJOsa3S5K2kdMQo%2BrS8WJpsT3Rew96VMfmftC_naRNQ%40mail.gmail.com.
