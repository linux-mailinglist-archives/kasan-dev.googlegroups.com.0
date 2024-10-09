Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC6STO4AMGQEZKS4UCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 912A899767B
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2024 22:35:25 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-20b583a48f4sf1833115ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 13:35:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728506124; cv=pass;
        d=google.com; s=arc-20240605;
        b=PkZzpCwPyTghqmvqVvF3ESJwQWvWh1XqBBOrvUNJuGEO3EZhkyj/8odZ+mBfLrWRHl
         FD4a7CJz36ebhv1tkLDd+Zm/U/b1cTupEwasHRHROYTWB/TPUnwL7jgVbQtHHCVHxu6L
         D9XXw9w7viz2JeK2FmTM3wZE2vkZdYt8ARxyI/uX3WiNGusK1d4lFGczHKM3hLxG16oZ
         9Yz2/UXBE3w9llmRxDA0VuZDE53hpk6MerJKxf4uPj+pqDNDsyiH1BPTDyqRH6oBBEjl
         mhEYN5nfn940PFsARbRPSgvtIPCWYsRm+3DlH6tUZ0Cf2r1Exel+JXBs1RD85D5cctzX
         CmGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=D5EZY07yMzYT9ZqL2b/bImqk/WZ+nLRE3LrkS/C9mYI=;
        fh=6nwnSEVXmVf2aAxIN8gHf1ERilfOUW07f6WKtpIekts=;
        b=BHURDnDcMgUCKiEG8tamPY6Imhgz/xWBetjxs/iGlZ2Fd9cuv11YNdUz2o2Xl79a46
         4fqw0oYMwmOpAMGFXeeoPJIQmITdzEv4sdW+j5RO2c7GrrdEUxiW7xrmWumKXACeUiDL
         Y3J5K/CnZtnaTU103G3w5LfwhvpJ8mtqZgOEAulJEfDywmu2/MlGThgBrtl7F4M7plhm
         b5lpuDaf1nlgJhG7090yTRKaeDqN3Fw7zmx5kmUAqoFVPl2W3SjSmGrxAV5jPFBhcd77
         E1A0jWA4tDUvkRm8e65Rt4pIvSFn3xaTnkaLsU8w0ISuyayBlUOFdELva0N9E3szQw1U
         DWMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oQwEfs8p;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728506124; x=1729110924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=D5EZY07yMzYT9ZqL2b/bImqk/WZ+nLRE3LrkS/C9mYI=;
        b=J6RHZ6/xDHxaBOr699DoOMO/MxO895iFYD04qVjM9jf+epS7fqDWUWd89eSnbCtBm/
         jh7BVWpBBKXu6dQ09YKdslYxfNeZJXGztAApHxWzKl1FolPw6Pm0J+YBeaX9C2jmyTZ2
         gbHjhnI2Ne1588QZnSZ5+dVxii5iVUeG90YDWa7yMXl4OGwlo2Wy9I7snAT9DWZbfLE9
         hD6HNCcTQyyAoKtKxFlI2jczQ++L1Hi4B1PAIE09YE7QPNDsriEjlM1z7OzEkNBRJTkt
         6zM0lXwhapRDm8r07xfxEFK2oCyYpPQ93DROHg88RKABDuLWD2XT387khXJJtWS4TWol
         L5FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728506124; x=1729110924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D5EZY07yMzYT9ZqL2b/bImqk/WZ+nLRE3LrkS/C9mYI=;
        b=vC9FaZRDwYyLZrtZh5cFFqUPqQIIEpHOyD3UPOp93hjirqxLUxRWySUS4tkLwXEZXo
         gbF0SJAaYBBulyjKNM4wB16JNMjicWM2dV2hIcsg2sXXr2+5JgbEFAbh40qfe5zK3rRc
         OhHW0/W8AHbDx8Eo6RqNjLf7KbfDFwhjH3ZhpnJJlwazNBq9y/kDlhevuoJ5QszZCKSl
         RVOz/1USKrap7gk2pudk1cxhlXv52sYBw53MSEdC7MLgibRKn3+3vyj/ijjt+6R3rYSl
         rN2kSsOSZqsT7ZWY9X/50e48dC9s7NCc/Or+G7thphdDfD7Ta59UssftGV0gtK7pbli7
         s7hQ==
X-Forwarded-Encrypted: i=2; AJvYcCV74fwZdE5J0ProwOXNe/2JClN+pHlbSuR5Yy5ByEGgJLzYp64kOpoCwKH6asoFdysr7JPS/Q==@lfdr.de
X-Gm-Message-State: AOJu0Yx8W9NFJ4MYj0l41bMm5LGMiqTAbALalxie7cqrnNg6mMZ7p3CO
	yb0MqgYIDSazO3jLo5b7bTwF0uurVtu52ztvPwwS+dq9wNQHp0DZ
X-Google-Smtp-Source: AGHT+IGb+r1vB21BpoWSatMpmKPV5bwnTiOqJmbZN3yKz4Ofs9bKGVERoC0xRweNqNUVGBz93snqAA==
X-Received: by 2002:a17:902:fc44:b0:20c:5e86:9b68 with SMTP id d9443c01a7336-20c636dd37emr66812675ad.4.1728506123375;
        Wed, 09 Oct 2024 13:35:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ccc6:b0:20c:5a7b:2676 with SMTP id
 d9443c01a7336-20c807a4ce9ls1936145ad.1.-pod-prod-08-us; Wed, 09 Oct 2024
 13:35:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwu32yRDHMy/pVNxJ4Ith4a5+pdpRUyfLHLGpQiJRGQbgNKqrk49NQcPbOZpBlhPqc5nZHZ2O3TEM=@googlegroups.com
X-Received: by 2002:a17:90b:e8f:b0:2d8:53f8:77c0 with SMTP id 98e67ed59e1d1-2e2a21e7d4fmr4807291a91.7.1728506122028;
        Wed, 09 Oct 2024 13:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728506122; cv=none;
        d=google.com; s=arc-20240605;
        b=R8tA0k6wc59irO++kmhgwq4aJTC7E7bNA1TVAFRY1DyNW7sSydIsRTrBV7UtQWGmtJ
         yd+PGzxP6CixuFU+9LOuo/0ua1VzgNK+taLlN1JM7p1sntetfC+uCb6EG6v272UkDvEL
         xeAEn9UzTK3VMcHitl6s0eNDR2qLf41qBL1HHfj+ohPwrjzsfjgKXxqdjEa8/DTd3iWO
         tIWcV2qmwZMW8+4hM+XEP1O9y+ZLm9kJ/mjWfXw0ShSCu9Eojq1p/sKIGMNvAITQM64G
         GzkJ2ZGJ54wZmNfAYytRDgapAI1Kk9u1+noLFmGxyfBnhKKAJZIDyvA6umi/EQMyNSF3
         iJkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GXLCkw65d2S++VNyv8Zo9MSqFS1XqxeG9ZueQafHMXY=;
        fh=17Sek08Co5Gfr+oDhQxm03ri95Gao+6AiQfbzvvcYwg=;
        b=HqOW5MzOiQJW2yWVscvcEqexgX+5110CSm1N3sT5IpIbkSoWfAfVuUU4s4lEJtnfDW
         0fDBF4O9AEKbZMf4LYwcIaCkhkN7M6otmiiZ/psCzbugDXCVHw80EZiBClspal24K+//
         oGqON4xYBCGpD5/FTK+nZBf2jeRCvFIYVDFnLbutlI0HBrKqFOPLR51JEkYjzzHuNGgr
         yvwwoRRpX1funyInL4oGpEt9XRlpKlxH05Oz6bwaW4xeg8la7PAg3p4Wfuf+FZoLovoE
         5iFgebHfr0v8g4P5u3QKd0bwAsVwhO/bkSrhBy8HeolCBHF0IEsjupziGxg0ZZb6xdj1
         0mbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oQwEfs8p;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2a5ccc44asi97998a91.3.2024.10.09.13.35.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Oct 2024 13:35:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-20b0b2528d8so1818425ad.2
        for <kasan-dev@googlegroups.com>; Wed, 09 Oct 2024 13:35:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/VAlwYExu3EjYGfOqtDri/iqIuRdZwuusoUSLPqtFHlEZFUzHMfGeFRBvtJQbyTfRx3//f9EPiL4=@googlegroups.com
X-Received: by 2002:a17:902:d490:b0:20b:b48d:698 with SMTP id
 d9443c01a7336-20c6370bcf0mr51380195ad.17.1728506121152; Wed, 09 Oct 2024
 13:35:21 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
 <20241008192910.2823726-1-snovitoll@gmail.com> <CA+fCnZeMRZZe4A0QW4SSnEgXFEnb287PgHd5hVq8AA4itBFxEQ@mail.gmail.com>
In-Reply-To: <CA+fCnZeMRZZe4A0QW4SSnEgXFEnb287PgHd5hVq8AA4itBFxEQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Oct 2024 22:34:43 +0200
Message-ID: <CANpmjNNPnEMBxF1-Lr_BACmPYxOTRa=k6Vwi=EFR=BED=G8akg@mail.gmail.com>
Subject: Re: [PATCH v4] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, akpm@linux-foundation.org, bpf@vger.kernel.org, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oQwEfs8p;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 9 Oct 2024 at 22:19, Andrey Konovalov <andreyknvl@gmail.com> wrote:
[...]
> Please add a comment here explaining why we only check
> copy_to_kernel_nofault and not copy_from_kernel_nofault (is this
> because we cannot add KASAN instrumentation to
> copy_from_kernel_nofault?).

Just to clarify: Unless we can prove that there won't be any false
positives, I proposed to err on the side of being conservative here.
The new way of doing it after we already checked that the accessed
location is on a faulted-in page may be amenable to also KASAN
instrumentation, but you can also come up with cases that would be a
false positive: e.g. some copy_from_kernel_nofault() for a large
range, knowing that if it accesses bad memory at least one page is not
faulted in, but some initial pages may be faulted in; in that case
there'd be some error handling that then deals with the failure.
Again, this might be something that an eBPF program could legally do.
On the other hand, we may want to know if we are leaking random
uninitialized kernel memory with KMSAN to avoid infoleaks.

Only copy_to_kernel_nofault should really have valid memory, otherwise
we risk corrupting the kernel. But these checks should only happen
after we know we're accessing faulted-in memory, again to avoid false
positives.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNPnEMBxF1-Lr_BACmPYxOTRa%3Dk6Vwi%3DEFR%3DBED%3DG8akg%40mail.gmail.com.
