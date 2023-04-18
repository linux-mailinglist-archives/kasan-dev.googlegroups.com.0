Return-Path: <kasan-dev+bncBCT4XGV33UIBBXNJ7SQQMGQEAAFEQIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CF4A6E6F1C
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 00:08:30 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id z5-20020ab05645000000b007667b72ef11sf4095242uaa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 15:08:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681855709; cv=pass;
        d=google.com; s=arc-20160816;
        b=QksQm8So7ZgXB+10yjUohMjLVtZswq6EbqC54IwI8ziIUxeMgMPtrNfgKJVBg1hMuZ
         F1Y+0kRNnxDbKEmb+7RSICBjM54xZv+vFQaBiceZT76WuwPlZ82JVhjkiyCIk5LSSxDb
         M6NTEGOO20/myrZjBHrwlDmlKGsl9R3A+EtKB81j7yUcw9EJwZtNq0g/QM4C+sp01RT1
         1+20qKwHFsHy1w6XjbG04iUX0l6oAUfG+RwO8jU/GXaeKpWtbgpmeGy0j0QoFWIO/uWo
         WIMpbJj4gbyHIa1BVmHUsj1Ajey9szDzvZMiGWgk5V2oy1pr7pfYlYnKkBwWgPWw8LDR
         FVyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=9zV9J+uH+eoottXMkdfsTkBR4m96wzf63MSlKqMFRXM=;
        b=nlpDt5P1MwcxP6ruXmAVncemqq/wmLewVJOfyc/ZXTXOqblBfEBM70X57IPljCzDTv
         ++2vwVA2JT+MRXot3NbucY6RVrZczM0isn9LZ8UWP7pN4DYf0Y/ES4E0vX8nYva+MiHy
         XE9fOC6qUp8v6zuFHqU6HIWd7yqbFam4wX64900/cEAU2Y4OZ1C7OjoRgnTGyyTaVr9F
         XPswTl5t8Zii8N47gRjpXi0oaZ1Td7Zj8kbYrRfU4DN5DSm4DYestNZT0HqAjjn/h08X
         V1H1Ee5EWEBKNR6RQS5GHHhR3dt6Tl3dAtmZbzG0b/F0scyroNtJD+uFoawVR0RXkdqg
         rZlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=L9qKdnua;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681855709; x=1684447709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9zV9J+uH+eoottXMkdfsTkBR4m96wzf63MSlKqMFRXM=;
        b=c4+JvdvZJw6ZmDQDAsGNNbDcNp/QkU2GtF4uFIskUwEtklPB4z1+tOs7Nlb8Nm/ATS
         rYsQ+RP+BnVqE1G4jQ74ZmkO4dF4FNhihagw3lsUOylp7kuqRYuDEnkZAsg215hSBKUW
         oj1H/V9z7eb8t2jlIWofQbixaONVDtv3PA6qurWUSn+SwNVWzHNALLx8tnkg9K+KOyXg
         Qw0G239nJTVyRIm9wzDYg4RvPjuCEEOo16yzdVv0CtQgk7zQHU1BfibWsT//eAqCSlf2
         ekTcYYflXBu8YpQaEHMYDH/FuLF35ZpZeJXtYMjgrpXSYU4jmAlWOP0/V6JaMtbtjK4R
         XxsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681855709; x=1684447709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9zV9J+uH+eoottXMkdfsTkBR4m96wzf63MSlKqMFRXM=;
        b=HlOZsC5eeSYvyV3yEzQtRYQB+eds8BCmLb9LZSPI2nJ6WveeSxJAp/FzsbhNkuTRpW
         TPH1rVC4bP9FJt5wqM/CVeOrChxHv+JbuT11s9aIme02/SEt2AQSPn8VlFUkmIQ9/4Mc
         RDOTPEPtL1orFNDDjRy8ZuFm4b5wbKn/xNfTJYLGr9+Fe7UiUHd65g3qBlh7AIHouZmk
         linN8i8O7qdlmLwu5/Ixm2bxSYvhUb/5YhGCSNHjKLf6kc1BMt4DzkPaCYvs1ud/nj4/
         qRMNP5nabcKMgcjtrhcam64xTHSlBW+HxEfTf/uhZTfKmcl6ugIEW+f/fgFgnSuiyb4d
         rwyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dYG6e0NEBaM1+bwg/bikxWtiV1mcp/Yoz1rZe1PlnphBz1uzrI
	o9E6BoRym81GQQ/DWmg9KeM=
X-Google-Smtp-Source: AKy350ZCjAF+w5LnRLem/orMRxZDYLa8HeOt9UkxIB6J9fRt/eTO91fmR+BNhee4FTbkjNemzX2z4A==
X-Received: by 2002:a67:d918:0:b0:42c:8e3d:74f0 with SMTP id t24-20020a67d918000000b0042c8e3d74f0mr172533vsj.2.1681855709257;
        Tue, 18 Apr 2023 15:08:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dd0e:0:b0:426:b068:aa4a with SMTP id y14-20020a67dd0e000000b00426b068aa4als2865866vsj.9.-pod-prod-gmail;
 Tue, 18 Apr 2023 15:08:28 -0700 (PDT)
X-Received: by 2002:a67:e403:0:b0:42c:80e1:ad8e with SMTP id d3-20020a67e403000000b0042c80e1ad8emr7408090vsf.12.1681855708520;
        Tue, 18 Apr 2023 15:08:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681855708; cv=none;
        d=google.com; s=arc-20160816;
        b=rJl9z0Sb6E/uzpWuF1NtLm4MuqOyTriPFrywsDETWxXC99G2QTpHwc3E91LwPTVYwM
         asa1iAQAYeTBVS9uZgLYujGz3SycINJl8C9ZGs0F4E/3BXZ4hs7PDQZMKLkS2Cwtwvz4
         pQPh0BkJV1KGlqf57ypkvRzdCP2+h+myszL3VhsKdgs2n0M5BL8bh5sGxWwgzpux2uZd
         BW7bMb6YZgVudpFe1bWsLtAkkMQ4jOHywsMseWz14PHvCjwPCvhSck0azMvOZlanidiF
         Pm20BK4kechTiscEzuUuWWJwIusAoaSBU31gnqmrQtUAzUWwIyL9LrKfgeja+4yA4nfE
         djZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=vVuMx9WS0KOp+1w2YtLUfJ1n5dB01HE1e9rVWICoV1w=;
        b=is2wh/Lc/BWYvgma69pMNNIC9Rr2V02Dd6lhM2Ss4gqYE426D85w/nnv018B4x0/NJ
         l7E6rqJsIrbBx1wyuVC3tTBh6dwXTsM5CZvNyKJzqaMuEULyDPaiG2H/c0+5mRlxOOVY
         Fi40/00aCaPAzcymcF+QGFRF229XefwodQGVf/uWfCcXNBDoVkar5BZSEPqlfunb+Z+D
         dtS3zt9R+9rYWU1RiYRPyucApxD6jZpAk26NnZRQbtrfaAR84rarIBqhox7hAmT4PAfV
         Jo6mNxISK3lScnkg6SVn9k0QO7uU3QvpauGPPHPbmu2sHx83S4eloKN0kd1bmhexsL5e
         WjlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=L9qKdnua;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u16-20020ac5cdd0000000b004409ac628a3si43522vkn.5.2023.04.18.15.08.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Apr 2023 15:08:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 031DA6307E;
	Tue, 18 Apr 2023 22:08:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1ED60C433D2;
	Tue, 18 Apr 2023 22:08:27 +0000 (UTC)
Date: Tue, 18 Apr 2023 15:08:26 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Zqiang <qiang1.zhang@intel.com>
Cc: elver@google.com, ryabinin.a.a@gmail.com, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kasan: Fix lockdep report invalid wait context
Message-Id: <20230418150826.ae36090243b21f21f3265792@linux-foundation.org>
In-Reply-To: <20230327120019.1027640-1-qiang1.zhang@intel.com>
References: <20230327120019.1027640-1-qiang1.zhang@intel.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=L9qKdnua;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 27 Mar 2023 20:00:19 +0800 Zqiang <qiang1.zhang@intel.com> wrote:

> For kernels built with the following options and booting
> 
> CONFIG_SLUB=y
> CONFIG_DEBUG_LOCKDEP=y
> CONFIG_PROVE_LOCKING=y
> CONFIG_PROVE_RAW_LOCK_NESTING=y
> 
> [    0.523115] [ BUG: Invalid wait context ]

Could we please get some reviewer input on this change?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230418150826.ae36090243b21f21f3265792%40linux-foundation.org.
