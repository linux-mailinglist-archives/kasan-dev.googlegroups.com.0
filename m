Return-Path: <kasan-dev+bncBDR5N7WPRQGRBDWF526AMGQEZ6ON5PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id D5EB5A23163
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2025 17:02:23 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-71de28807b0sf682402a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2025 08:02:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738252942; cv=pass;
        d=google.com; s=arc-20240605;
        b=L5PJ+MEZHZIlWzEVKN3MuzPO4f2m6wz8rbL8DgFwtE30TPP+BsKXJ2tLYptUt4caP/
         0sd8YtJ+t8LEyDYH1Z2SArJO7e4TV6b2tP8J4/+s21Ll0cy89Wh9axwSZmT+Xg8SWAHW
         2a02KGlQPXdNjJDwkh9uPRdA0t1p9XbzYfcjsCm32s0Nh8+cuVuKHtML8Hq8XjiGFuG5
         jIk7dfwMxi9lwe3h6X9iuxBD6eSLm7ZXmbYarW3cTYx85Yzu47EtrCgUXcaajd1jSyth
         S+ezOuLGE/qdI4GRuvOBDIqtJFz9EaCRTMKCXdr7mKSCNKe8RHaPKTIKq7HLTeMtQHax
         ZIlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=K9ySiOAGOuoI/jkZSsd6GudizxNaPRghWBFQSEw2n0g=;
        fh=1MJWCSMHhKxgJSPbGvImRUMeQTR5IEh30M3awaAZn6M=;
        b=TkLBqV+BBICyQzeAQ6V0W2F5kar+Kl2q0Z/2/v4cAvmAMPvZVxcjyLGDH1YE3b0WCY
         xYdiw1ZBZx5fERLRnyVQ64gfCccDvAFL0b+cSva7Wd4yniUnsvyyMehv75usw5+6bxJu
         8s1YzDEq0SIx6xMAeZjWsVOnxoHnZYi57NBw/8ZK0G2JyDHy/L021KtPmNF+s36stPT9
         eFlrDaDzYq4cWI2sRMlLMY12/XNmd4Y7jYzacII4ys0aeahh+/w1+OeMvNGwpUXJKG7v
         qr27ET0gqm3qNXlf1UT7hnhjD2YJXcPE2KExqw9RkeTMcmdX96m7LMJsfBi1y7Xs4xR2
         hZKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601 header.b=1IQpzCD6;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738252942; x=1738857742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=K9ySiOAGOuoI/jkZSsd6GudizxNaPRghWBFQSEw2n0g=;
        b=eQ9GzzMtrozrstd9Z93JjOTXzFBlPv8At1a/AMr+o02JYfvMOKA/8hpWKC7ANDlnOe
         xom1fWjfxZn/IExKVORmUj9cqygusTAhbIsvI+SW4BAemUx/4180mEbrwjcJnts8raui
         nHzb8ilNGsgXdpe9pTSn1BO4aZGKD4ddK22J0q/Z9C5eqHlrZdexUF4T29eO4dc8ZgpT
         bFFbDXdz2b4/iwRvq5UW10QsWYCdK0z1EszbcAKUvv27FDAdAPnwo/5G2s6XhFunPTkJ
         x1BCh1p9EYg19ds8LYntUU4BUdzHwxwy/dd85R9yhjUPoxlp/Lo7R71O/uC+6o/BqjO8
         uwJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738252942; x=1738857742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=K9ySiOAGOuoI/jkZSsd6GudizxNaPRghWBFQSEw2n0g=;
        b=VTyiGaNeW3lGsWej0bZpVJ94Q3NqlfZYh68LshxMYvpqqZhT+lm2vuN3matcnfVcHy
         1SKI8dT0hKp10RBSWF5P1RIYUzPX0USVYQNgbHqn2Cb2cipEWLLZqRBpVHgTxJawcNJs
         EftbmjcRz0aavxMwSTrdDGpq+na76QK5RdW+HrqaMMPy6Z2kvCC7c0IsrT3L5nQOm02m
         UEy3QTgICB4ofozghQe9YpRsG+yJDm/QBT9zUzER0oLmEa6l3Jt2O57ylD0MQBOWGSjl
         YMq9p0pWBI/Ap4NdNMpD33Z76OH8pI5W5YWsPqZFb7C7LB4xz5BQBihU+ylQQQ/PQJPG
         ue0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1YKPJ9QqOm8PTs1WFZW63Wvclre19upDGYuD3/t30jpFPUxONLpx0Q37lInXWzmy8u/z94Q==@lfdr.de
X-Gm-Message-State: AOJu0YzcRUh53Wfiana2egjWKljOeWNq7NfpQszJKymjAYQ4+yNdrkH+
	lWHk2Nh6ZBTqDnTk8UeCwZq8HX9PXeDUNyov3clnaSiTH0zcmhJd
X-Google-Smtp-Source: AGHT+IGqWkoMERrwDzpRZvyFhO6/1BV+hljYPzzcQRS5s4Hxe986o82y2LkruN2mb8ypnmFQXR+Suw==
X-Received: by 2002:a05:6830:6212:b0:71d:6314:40dd with SMTP id 46e09a7af769-72656792d16mr3989885a34.14.1738252942301;
        Thu, 30 Jan 2025 08:02:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d255:b0:29f:cd6a:5ded with SMTP id
 586e51a60fabf-2b3506fcc33ls466575fac.0.-pod-prod-07-us; Thu, 30 Jan 2025
 08:02:19 -0800 (PST)
X-Received: by 2002:a05:6808:308a:b0:3f1:f540:e6db with SMTP id 5614622812f47-3f323a56073mr4485420b6e.17.1738252938956;
        Thu, 30 Jan 2025 08:02:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738252938; cv=none;
        d=google.com; s=arc-20240605;
        b=KDU4NjHWQUKomM9JklG+eFaLODKt7X5M2kbdKRLgankZ6I9u92aJD2Sh01RMCxth56
         471QMPrL8iC2/ALYrGTC6mAZlwrw7lNYffEhgWA4sBsV84Wt5F0dCU4CZZvyKUvRN3PD
         EZ+8UkMQvfDq68ouGM8j8ZwrFl3CInku6CasedAgUrvnUNfznW0F0uJ7khCxo2AgsLI+
         8HoeEssPGeH8eLCS/muMBFW4ERmzu543rMOvIfm2bi4ZWCgAy80f2hG7TJykpp6QFsQ5
         DlfmqaD8BJ6dkaBwR33Rw1JT5hAcCTXDsHSxRfiI2rL96lQLvinF96pdq512YVuuUkWg
         s59g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ltspuTTT7wImpABc2X8tmjQrqpC9O8a4ARLx4Ty4zio=;
        fh=fYK3Mn7RPj8Ff6g/uFaU1904PyZptm+vTTNxPwptVHQ=;
        b=gvl/RiOrGupNE5C9dTV6kGzP8xY05qzI1ZvOkiqO7UAFsvwY6KqunigvlxiQPCNDiw
         jZIwyqda/2yVgAENVkzkGalOpO+KaOiQEyanXP+V5fYiCgakE3wltWoQ4YP6PY3DLMpc
         IGydWjG5K0F0AmeneiBlknfANe7cES6RWOIBtKpbfaemet9nApnG7SFVzGfMI9JN0HKq
         DrTZ3xmTFZ6FzL0mbIx91zq4e1f2TdZOvHlNPPzMV0fvJAkTBq7641TcN3n8Hg13FrYP
         k1OKY29z5pxGS1gp4CTCAOw0UVYcbwgSUiZyHVwFxsQoyq3a0TO9BVWW7M7QHaJifUgu
         UC/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601 header.b=1IQpzCD6;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f3332b8df6si73700b6e.0.2025.01.30.08.02.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jan 2025 08:02:18 -0800 (PST)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id e9e14a558f8ab-3cfdf301fa4so3073855ab.0
        for <kasan-dev@googlegroups.com>; Thu, 30 Jan 2025 08:02:18 -0800 (PST)
X-Gm-Gg: ASbGncv6kNufrsp9P+vkDC5TNldRktW+XM3ljtMi4NQOEg+ae6axwz+OSOPtFcBD2Io
	zUq/r4QCLP6YoZnfYLHuZcBFBm2qQfLjDBLSgUoAqgjkJ62RDm7hHR3W4KW2w7PpMz6BcwMd5SD
	NbJ/u0PwmV39+MOSTdJ5iqJ6dlBH2l2rNGrjDD8NtwUdcda9vIDLliANg0DsoQWREvTbD+nFY/O
	wZi+nYALC+b6HLp3/u9RN4oJnlC9RnaFsyqykXkv6G5RuDRiGZAtyDEbQHbCZjKaEXdB8GSDQej
	wtOqr9SopX0=
X-Received: by 2002:a05:6e02:17c7:b0:3cf:ba21:8a20 with SMTP id e9e14a558f8ab-3cffe470222mr76274605ab.18.1738252938099;
        Thu, 30 Jan 2025 08:02:18 -0800 (PST)
Received: from [192.168.1.116] ([96.43.243.2])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4ec7469f02esm396436173.90.2025.01.30.08.02.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jan 2025 08:02:17 -0800 (PST)
Message-ID: <04ca477d-36f8-4b5a-b4b8-a33afc75d144@kernel.dk>
Date: Thu, 30 Jan 2025 09:02:15 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan, mempool: don't store free stacktrace in
 io_alloc_cache objects.
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, io-uring@vger.kernel.org, linux-mm@kvack.org,
 netdev@vger.kernel.org, linux-kernel@vger.kernel.org,
 juntong.deng@outlook.com, lizetao1@huawei.com, stable@vger.kernel.org,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Pavel Begunkov <asml.silence@gmail.com>,
 "David S. Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>,
 Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
 Simon Horman <horms@kernel.org>
References: <20250122160645.28926-1-ryabinin.a.a@gmail.com>
 <20250127150357.13565-1-ryabinin.a.a@gmail.com>
Content-Language: en-US
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <20250127150357.13565-1-ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601
 header.b=1IQpzCD6;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
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

I don't think we need this with the recent cleanup of the io_uring
struct caching. That should go into 6.14-rc1, it's queued up. So I think
let's defer on this one for now? It'll conflict with those changes too.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/04ca477d-36f8-4b5a-b4b8-a33afc75d144%40kernel.dk.
