Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF4L4SPAMGQEGDKXMEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CD033682C51
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 13:12:08 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-15fe7396eb4sf5472979fac.12
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 04:12:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675167127; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZdHwvx85ImHzNDcwN2QaHXJnvo1i0f0hyIaZIQSv4Qup/mfpdestpEzA6O3VFhYbTR
         w25AlYfY7ydvnzz/shm+MxgMp6rg8pt//OqpgXRCGgCW+/NjDJdSjK6G975eKBXkk9SG
         kqsatDv8qBEvI3DgTpbEpkiVa2EQYr3JGbMasmr2C5Kiu30D/fesXATNUN7Jbh1gMdvs
         mC2S2D6opcUmJBcx9YiRLakC4TAfQ/Y0ZHxLhdZwcQhH/XlyBPJt/vbAp0Wz2kxATAPv
         E8o70PZn2pbDIpuFwTExxuDi+Q2NXtNPO0ozvF05MtXi1FLE+Am9VVy8aXNIIzTeq3ZU
         IdhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q9bpglK2hnieRJtEu9Thr3EClcJscoHw+NUK6xcXgCA=;
        b=u/+QJqFuSnFj68Bmr/L5ozwWScgePOKSz3XYT+7t1MsCgJOxz++Cr+ujVRQWvRbsj1
         SG+q1JH7Xk2IhQMm+A8E/zbZKiqgve6PRva1wv69dW1yKzv5DvBMDJCEj2RONOKvHOK4
         M4xxGp2G7ltjSLlm5HKEnlgye9aR1POejiAZ9t9kpTlDm6TtPrZSwvtPySCVb1pnMy1O
         KGPeKE2aJoPwPFhmRBcIAxoEuj6dJiqHnLC/uZAAe+BbqWUcrzVv+8cGhrFmShG6LWSu
         M9DP070VMTOREsvcU3r6ccaxJNfL7sPo9WMB9epUMZYWM3QpMVCp/yDP0rMwDqs+4HIF
         UDEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cXTGjj9h;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q9bpglK2hnieRJtEu9Thr3EClcJscoHw+NUK6xcXgCA=;
        b=bMv0tAn885UJwsC3DQOP2s1cxxdZzApaogQBptWdpqMvo/1bKirei+5HEpkJkaKgRE
         DiafxHEzM+CWJyRvW7TY6lJcfQFfNOx/uRu+srXnT61Vdj4IW97eWmiVwiYJmED9qX8k
         R9xMtYceh4sXlXEOYfCvIYL2PBXxTXAPJCfmx38UPhOkd0jgs0fColLJmMPRVAVBHDHi
         7K68x8kcY0O+eOtJT5q8/VkYVYpX5JTV5RNf7ZwNj572fV/RW5Z+oJtg6X8clvOQEKZh
         ebvXYHdbq7/JH7THOpW4fYz8/dmNYzAMavxpKe2vtYZvykrY9fLAsJVYs547tLvCQ2ii
         BJ8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=q9bpglK2hnieRJtEu9Thr3EClcJscoHw+NUK6xcXgCA=;
        b=AfqNwlbad5u4Prhel1114SmE0hMa7fFZASGuuclzS0YmSvzMO/+ZBF9BRM29PgA36X
         /mPZipMoRy1cHErxbj8u6JfQt++hH/UltZfVT/mbC858GaEvZtHQViR8yTXJ9niq4Q3o
         ude3CQrXCFspPjYf1AkLvS2Df24VnJ5VaJu4z3zXMu06ndYyzDZReUV8e8hw24HmHSPn
         50K1Y7x9mNiLjteIM6g4Mms7600RLvjMao2hGccMzd8lOc6AENOfaRYZcrvUVO/7zbFj
         sS+XorXSfWiB7wZTD6I4KceMt/n6EIj9YepA1AkuUrkCGKMXDu6oydPFSH6mCac9a+nW
         G/Ug==
X-Gm-Message-State: AO0yUKUceScZy0I8gxYYEvy8gG3VfHYWn7o/JkrrpTWzTzeUyHTT2kxN
	1sEQn/AWmcRFDF7oxYuZPxk=
X-Google-Smtp-Source: AK7set/snJSyeH0zKsM/H6xB/T6T2cNvNBxpUOtAjPdZoU71yLQxsuMRli2Vr8d7xnxsCJJmKpmgCA==
X-Received: by 2002:a05:6808:2d0:b0:378:721e:ab8c with SMTP id a16-20020a05680802d000b00378721eab8cmr316256oid.4.1675167127357;
        Tue, 31 Jan 2023 04:12:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5687:b0:150:4546:6415 with SMTP id
 p7-20020a056870568700b0015045466415ls6481166oao.11.-pod-prod-gmail; Tue, 31
 Jan 2023 04:12:07 -0800 (PST)
X-Received: by 2002:a05:6870:b3a0:b0:163:90fa:73ab with SMTP id w32-20020a056870b3a000b0016390fa73abmr5671369oap.45.1675167126944;
        Tue, 31 Jan 2023 04:12:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675167126; cv=none;
        d=google.com; s=arc-20160816;
        b=yaD2KWkDcPHEq0jcEKVGRHrK0CU/2rSymzOlxth6/fRqKq8IGpGQrZMl5z1ab52cIO
         yTL0oyMyGAYmkXvzWcHMn3Zxnisp6VHXxvFBpW2pOXSKoGHvGC4Fn0QC5FkqhUml2AJ+
         ah7GOf81DZ8NVzM2u9uetDiRdidrnU1S5JcCAbJdGmVtLhlFKgtNR/06Y37xJJmtKUIv
         qIqiCyOUN1t3tH8IgeV4DqokafFSBPr4vYyLmgoE7O9ogs8256FEsZuZZi+Wv26BHdog
         0zB7nC3boiudIUTE9WaJ35hZ5pdcTThJ3cDvj82ipg3gqPHzZcqXbCEc/BT+iEawHTK1
         JH4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xwKtXvIpXGYzIeHgL+KLVHN88KKoCUct+MmNeO+2FwU=;
        b=pVI4csl72DA/65Dif6/0bUAGeXLBnhhIJB9V2fgi8yrpvKyCsk1TRqa1+VUtkrHXf9
         lHz2Pzstdn+QEq5MJewlEpXX/VBb1wQ93Qc7Iop5Rxgy91HONBmnqXiz2QFUtKVpkSHL
         KpPfRHH/FqUH9XnC5h4EQUbTYXZ/8K/bE+UERRg5x0MNj3yeIdGguwBXL0siHKVfU/WO
         uAxj6TCEdtsWSJmQMLu5K4pH0tO03lrKtD96aaD25SfA9vKDRtEVGACLv8JvTuhaLSUn
         StJKP4LX/yaIjR152eLnAglLekAdPekiaaXMQMVamjA7BD1/IgI5Wd70dBfMQ3mhB+J0
         rxtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cXTGjj9h;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2c.google.com (mail-vs1-xe2c.google.com. [2607:f8b0:4864:20::e2c])
        by gmr-mx.google.com with ESMTPS id lk3-20020a0568703e0300b001627c709dc3si1182154oab.3.2023.01.31.04.12.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 04:12:06 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) client-ip=2607:f8b0:4864:20::e2c;
Received: by mail-vs1-xe2c.google.com with SMTP id 3so15795761vsq.7
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 04:12:06 -0800 (PST)
X-Received: by 2002:a67:c31e:0:b0:3ed:1e92:a87f with SMTP id
 r30-20020a67c31e000000b003ed1e92a87fmr2324410vsj.1.1675167126314; Tue, 31 Jan
 2023 04:12:06 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <d9c6d1fa0ae6e1e65577ee81444656c99eb598d8.1675111415.git.andreyknvl@google.com>
In-Reply-To: <d9c6d1fa0ae6e1e65577ee81444656c99eb598d8.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 13:11:30 +0100
Message-ID: <CAG_fn=XRQ_wn5+TO2Djh7bXH_jLKpHgPLabDyXuFBTaOd=9v1w@mail.gmail.com>
Subject: Re: [PATCH 12/18] lib/stackdepot: rename handle and slab constants
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cXTGjj9h;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2c as
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

On Mon, Jan 30, 2023 at 9:51 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Change the "STACK_ALLOC_" prefix to "DEPOT_" for the constants that
> define the number of bits in stack depot handles and the maximum number
> of slabs.
>
> The old prefix is unclear and makes wonder about how these constants
> are related to stack allocations. The new prefix is also shorter.
>
> Also simplify the comment for DEPOT_SLAB_ORDER.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXRQ_wn5%2BTO2Djh7bXH_jLKpHgPLabDyXuFBTaOd%3D9v1w%40mail.gmail.com.
