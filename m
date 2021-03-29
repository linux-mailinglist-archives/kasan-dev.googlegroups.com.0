Return-Path: <kasan-dev+bncBDPKNA7WYADBB5XWRCBQMGQE2UW6JXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D271134D925
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 22:41:26 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id u27sf3113252lfq.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 13:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617050486; cv=pass;
        d=google.com; s=arc-20160816;
        b=n+JSjx+apFFnoKaLSYRkosR+MF1VYxtmDteQ21QHXnGbfBCvtEjGfboLmhytQ0/Xm0
         XyaOFck5d4330ttH3U1211nVTT3/yg7uZCbOJTSRdF+kcRVGbrDGAzMBH9t0XFc3bXnT
         tGOwWRySCZhc1zgxWhbBDec3wG5YWqgq7XnC3BO4mPQsGeSFUvN8RVH+nDXIooBBp6dl
         yPznJ32D8FvoWzN+JLT5nA9LERffhoxpBIn//fY/JK/N9lEsuquXQQUGhIMsQ78rM9Bl
         7fiVmNUwmec2t9lc4s/1GoC2gmzHaDjNfPpr5IQ9NIL/EYhoD1yNuf+gPutBUlshidag
         FV7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=zU2TcG1Xd4Q6lOW0TJbu4Z+RlW/CcRbqDqZ6U8UUJzQ=;
        b=PXzpsz+shuejIVt0GDyji3bGp5sNynj0Zpad1pm4Ag90nLEpPogg6pbC8qjB0lT3V0
         PBNt71yocSN2SBdlX+GrRcssK8QGcy3dIUfiFRS1Fu6zFQv3aJ6LYTT0MvUhnuETnjvM
         nb9+CWIq/jByjKOLU1TPJvypVI1Ieq/SxvwPcLR0FdI4ht+UyBtfzE2iEfQVzyMCu9kU
         zjNvcVvGb7ksVzCw/AeDQ+w+wKdeZNrghq3p9Ik3q6hMTcugZIa4qIOGrn8SEjcmPyUU
         LYHXeIAXNZN5uGMeRcamuEUBV/mc5r1PG7q3D2RRUZGboP9KXgnDU/N1weEZFuzPJRB9
         M4VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oWb6o1aH;
       spf=pass (google.com: domain of luke.r.nels@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=luke.r.nels@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zU2TcG1Xd4Q6lOW0TJbu4Z+RlW/CcRbqDqZ6U8UUJzQ=;
        b=qItODP2gW6QiMZv6HhN0J7N1/RXHpam1OqdC4b2US76CnQQHV8l1nBMSlINYllU/Zl
         hjd/50O9IfQewTKRsdDsd9ccBlBQgctfP1tjix6nBQNjqb6rFbpIU2oGMjg4GZRF82EX
         mxm1Zn50gDJ1thP4CYQu3lsf5WwEzfUlBjYNvw0y9Rj5E4hM2bsSJWcneyxHOa3lOtWo
         wLzBnQxwuOFrJVNieaVl/w2DoEKFtMbC1NWQmD0GHs35SSiBbVWHL7gY5fAGdiS/Nu22
         haKtK8MttHByzKkjbyufY9sc/slPBre9MwBcftu4tpRfdBYjClsWsZMY9+xrTy7JUvCM
         3lJg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zU2TcG1Xd4Q6lOW0TJbu4Z+RlW/CcRbqDqZ6U8UUJzQ=;
        b=FeFdfNJtnJN5kBYF3v3+HXjhaQ2y2LbMlP33V3c7CyZyDqeh5ZdHJfwNxrPb3asZ4Y
         RdC+egf3+AAEyfbT6Usxoh08m51+gKMALql8F2f40k61Wba7hxFZvrl81EH/f04kacym
         s9hh/3EutRowG6R53VVwbr/P1SsR9ZoeYcAnYNDw7+LhMy0fBrMrtftD8te0jDXm2ydh
         9K6/LWD2vbIdZyGBN5srSLSGjs75G01RMYWrBadP5e9kdQaWg4Ao0h5yxyWABKl7QWDV
         a15l2DRqSk6kXL9svTJDTB+G9qvuVLer6025Px64idhNC3cXFcFWbwM6WfTCKVsOLUfa
         hQsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zU2TcG1Xd4Q6lOW0TJbu4Z+RlW/CcRbqDqZ6U8UUJzQ=;
        b=G1jVemlGekyESUHH0Z/nAzsmumjDcf+BnwcXVKSvDFpcUgmJ24CBNhbil4gypayabG
         xB90LUlD3ENqNoAO2rSINKEdp86Vd/2rhhFjT+pyEsPKKeJMqY1sguwuLzxWBWQl9zjp
         uKB6+GMVY3D/PfsKHzq+Fstwq3THHOcSpNP02wfUQP2rLXScXdqFZjipMwiqGdalaait
         tAm+JglJFOER1nHiLTvQ9OUd5vNUv5VTUjdOKcUMK/FricfkDWZ5fbiKRpzNxGmYtskL
         v/3FB+Mj1g0+tm248dP2QWoVl4Xe/eJQTH6sIFdj0g2GUIMTOcTxWLMTIJac81aF3Q8v
         pexQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Uv4Od6PuhghvH28LLa4LExyI1CqGLxnID9lQbwi0Snua8zQIg
	d4Yjyqjb5skT4Lk9BJWQmN4=
X-Google-Smtp-Source: ABdhPJweHgszTgb1RakRyAvfiE00Cu2FsAnSYyfzwcvnLrj+GtV9gXv6tQZa2DHY6ljGr1xWa3ggIA==
X-Received: by 2002:a19:ee11:: with SMTP id g17mr6578333lfb.459.1617050486420;
        Mon, 29 Mar 2021 13:41:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b54d:: with SMTP id a13ls3441879ljn.3.gmail; Mon, 29 Mar
 2021 13:41:25 -0700 (PDT)
X-Received: by 2002:a2e:bc25:: with SMTP id b37mr18914842ljf.342.1617050485197;
        Mon, 29 Mar 2021 13:41:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617050485; cv=none;
        d=google.com; s=arc-20160816;
        b=Yf3hiPHVwCPrLgR4MnUBH7mAIZS1wrEsBN5l2VtXggCXwBC7hSI10Zdfk73u95GaUg
         KxPNVBAZ5PM3PDoj6wN2RweUWVz/bDsdbXcAyL5CTSAuhUMPS2K6m4xmnVy2qfzVwn00
         uL51RIK28W32SUGhtN1O0elAXYpPNATZm8Z10LI/b0jYL5qkayYqk10dA1JcW3rba4Mm
         hA5/RMY7r7amztpe5cPl0bey2mCWAIfi5qq61HJ9HE+fSn7jAqX/43bPLkkojvvzJIKQ
         QEd0esa585FfQ7ukEg85iI2geqo04JCWBwR1OI0miiakp4owqSkbM/s1RuvgfAH50IMu
         LB6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IOY00wZMw7iQ/C8A6RUq3HCwcrBzQhlsaRdSeoRLwXs=;
        b=guSiDJk9ymQvE89Ma5w1Xu+D5W67/SgGKcQF3zJkqVlbKflegGISsbDwg8EUIjjpUQ
         O2z4ZlP5Ba0sN2e6YgnS1m6/8WeITyqidLfdwAvsO0V949wRWZ7Ui3UQnJN2hmwel4IV
         nG1O9bK5lCdVYIQ+vwPLm5OLItA2ENN/cqoblgtXBaaUfEYQ6D2eMoDtG71chWBk4x+l
         anmaeg7w1AEpV1XedY0FIHxw4b6dQQTofFSog7XQfsLb3lekiH2y55HzYF/DYmwVUHGi
         2vQQyABkCqsKLwS1mV12pNNxuvVtUUb89msXEC1L/3xrr6d8y0cgrY8aNIk5cZtIHui8
         ntSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oWb6o1aH;
       spf=pass (google.com: domain of luke.r.nels@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=luke.r.nels@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id p18si662221lji.8.2021.03.29.13.41.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 13:41:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of luke.r.nels@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id e14so21435826ejz.11
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 13:41:25 -0700 (PDT)
X-Received: by 2002:a17:906:73cd:: with SMTP id n13mr29275638ejl.535.1617050484980;
 Mon, 29 Mar 2021 13:41:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210330022144.150edc6e@xhacker> <20210330022454.3d0feda2@xhacker>
In-Reply-To: <20210330022454.3d0feda2@xhacker>
From: Luke Nelson <luke.r.nels@gmail.com>
Date: Mon, 29 Mar 2021 13:41:13 -0700
Message-ID: <CAB-e3NQ11Gnoa716nnZ2tTgjb02_eZOf1gWn3YMmueEAp92c1g@mail.gmail.com>
Subject: Re: [PATCH 6/9] riscv: bpf: Move bpf_jit_alloc_exec() and
 bpf_jit_free_exec() to core
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, 
	Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	Andrii Nakryiko <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>, 
	Yonghong Song <yhs@fb.com>, John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, 
	Xi Wang <xi.wang@gmail.com>, linux-riscv <linux-riscv@lists.infradead.org>, 
	open list <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	Networking <netdev@vger.kernel.org>, bpf <bpf@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: luke.r.nels@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=oWb6o1aH;       spf=pass
 (google.com: domain of luke.r.nels@gmail.com designates 2a00:1450:4864:20::631
 as permitted sender) smtp.mailfrom=luke.r.nels@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

> We will drop the executable permissions of the code pages from the
> mapping at allocation time soon. Move bpf_jit_alloc_exec() and
> bpf_jit_free_exec() to bpf_jit_core.c so that they can be shared by
> both RV64I and RV32I.

Looks good to me.

Acked-by: Luke Nelson <luke.r.nels@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAB-e3NQ11Gnoa716nnZ2tTgjb02_eZOf1gWn3YMmueEAp92c1g%40mail.gmail.com.
