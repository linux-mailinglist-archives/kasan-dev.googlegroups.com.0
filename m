Return-Path: <kasan-dev+bncBCT4XGV33UIBBGH522ZQMGQEEDEUHCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EC65912CB1
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 19:55:38 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5c1a6660f3csf2600297eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 10:55:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718992537; cv=pass;
        d=google.com; s=arc-20160816;
        b=x+sI6DA15wf5i73bT71VAh9Ma81obMYewKG2ndeK82qRyYOERvxYHypxwBKLtdJz+/
         gmxnTyYteXgjXzXtq5dWa3B5hb8Tg/Vo7JNzUcZC9UpjOmGRe6DBRglD3Vw6ygkI4yMG
         T6lIfS5Ayw1vjCUST48jsIa4jWnHH9YJKHTTj+9fQY02sp0HzYWexcK4ZNLge62WNYue
         vkUvYbO/tkv4lrDyFg9TpEhEikDqTgFEH1pNCJem+W6lCD4b310SvyAKxbenkUB/shXn
         ufOpL4a15MrxiOt5au9nOAV/Q/6XxItAcykBlxgd/jyO9iOingWSo1CrgUXBBvOpUMpa
         Cs1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=sVbZK1DGyTmbYI9x62+TOLcZgw3j+F+XLmLRqYEBSTA=;
        fh=F+MF0CfHMPdoDbN92CmdcYwSI5RJMKeo3xD3uQ74Eo0=;
        b=KlJEOhWSo8M9iD4qCTYvSAPMyfCFJyWLHfS/oKxsFEkIs88vnq1GqFbeShzb5YHHvv
         FXUD0vIzrQoszOpN2mE2JIPRFRHew5tYFB4m8TVkLabZrE/HjyXvx2/H74GL8uNdxZJk
         GbYm62yKPKK4L1zpoZcirAAHcNkkqFAONj8MaVY2dr8RXtMvmn4yz2HwJ5bSeeGIc/j4
         XfMW7m01ZPIYHOYu+5fyXXAs9QV/1SFhKzqQuU2tuLkO1/UDoH0wuD7mAdk3ET2f50h9
         syF/HdamWuUj+lz+46o0aLGrwlV3PnYQmOW21ahFWVsh/s4D7BrwMGXmk0Ur2BjtIBLr
         ckqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=bwwQ7lsC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718992537; x=1719597337; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sVbZK1DGyTmbYI9x62+TOLcZgw3j+F+XLmLRqYEBSTA=;
        b=REBfEHS76x98893ODSBAWuitJL88rhU3Peh2DfveWZo2nAXfi4ntG4i9DNV0kG3Jrg
         AnNszYAd+otPLARvORcRuupvirJr5uZBTXv93Zm86XFpM38kAwCbB1yj/fvus5cnOw6U
         LoD7CWWeAg6KnyOI9N4AF0yYZgMBVjPCHgFkF9M78K8Wi59xMW3w74vuidXWiC3UTFsw
         MShiPFufrHmdIjviDSvAIuFhbgDSuaYcWcZI68ziGoh9WviIhvZYZ5P3NqhlTZV+27ke
         13ILpNtjExUF6qb+6oQzYnkqGu1QVZO5PsiRgk2HQ6oQeBCoSiJMv60WlzECoMWY8K/N
         cP4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718992537; x=1719597337;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sVbZK1DGyTmbYI9x62+TOLcZgw3j+F+XLmLRqYEBSTA=;
        b=aywIlRPOZv5yWn9unO4mGV9SShIFVno1/OzVNF6R8BIn3EDgEuUkV9eLXhg21UBJBK
         Le+0zlZViJ1GQYXv8etvZM8hF1CP1DoaqnxsBxbcAr7rC+LGVSmCytRlJQb54rtwd3Ye
         eE5zJdZMIfALkdGbH7mVmqdyE5U2suZ6yAxX2QcgsAhY3sON9K1B690NxhasaW8yLs85
         cZH6xekz+3PmOdb+x4FnRNXeBgZ1Hil3gxq8/0+2EeFkjb+QiX86wnfmSYqhT/s9l60O
         TKeK/7iAFtT5qmffcK9YLTQUtzbKLyKHGiojcgDprQ9V5ALzulHxdjquWX7VhAdtsbvG
         6ahQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQIN5M+cu9bJ1i3kM39EpqJTQiQm7Z/gcKQs8huBklNymbT0kr7D7O1ie0YotKdKNsI74CbtHSCNWU4FJQ33wcnVyZ54jypw==
X-Gm-Message-State: AOJu0YxFvirrnucSLzvKlvoKT1SUk7gQ2LtX3ofJlf/uoXkcO4HIiDm0
	fouec+3q+jq8yIIgkXcuGsrue9vyCpBQpVXiGGllCqDibBq/TT6O
X-Google-Smtp-Source: AGHT+IFv7wg6qkgj6j6lZWgAkRA4p/Fh9Df3o7uMf3ytoE2efy42gskhW3gkmqYmdSfeQQ+Xo8zGlQ==
X-Received: by 2002:a4a:8482:0:b0:5bd:c2b0:f599 with SMTP id 006d021491bc7-5c1adc11922mr9452780eaf.9.1718992536924;
        Fri, 21 Jun 2024 10:55:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8008:0:b0:5c1:ddcb:9923 with SMTP id 006d021491bc7-5c1ddcb9980ls566190eaf.2.-pod-prod-05-us;
 Fri, 21 Jun 2024 10:55:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCAFb9NHiqgQ19CP7FOPaCTf0mCtnZerFRFnMCt3D0DiuWLfd6qz9OpHOy4thYobknkLe3z1RzFcRxTbBTI3OJ29CheAzt93W9eQ==
X-Received: by 2002:a4a:858a:0:b0:5ba:ea6f:acb8 with SMTP id 006d021491bc7-5c1dee734eamr1643703eaf.3.1718992535966;
        Fri, 21 Jun 2024 10:55:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718992535; cv=none;
        d=google.com; s=arc-20160816;
        b=I14fX93RZyurc9MoQ1D1HN6Vr9Lky6gnFpX/6I2//Fcbtu7Sjj+mwUF9jEFDo+TyJi
         Q3AuU5tZDth1Qd8lnGtzjAXy8nvie0Wo43A8gi2qEPa3vfQ8CpAmgKbLMvikW9ygenCr
         APjIZX10NMFvhTKnNQx1uI4oxg51eRyOldPBUeEc4g8n7FZQmhBY72HtyJHppWzbsfRG
         imBGsEKxysFt6oItQH3rhSc6AIy5JH4Q/8OJDXKz0gFh9/hBZ9OP6uZp8wD6l0N6WItZ
         OOFrFBPN3ix0c0yxC66QPaXm2STo1Q0qVOfWwrBd31cMJb+Gs2Uw4YxGLWY0xI+1w01P
         ksCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=bk93l+XScdLpThWDVULnHRJsESII6RjkbiUbksfRVxc=;
        fh=hpg9AHKAqcSUjLLvvJ7M9bN/ipOUChddgKbN1ufQ0TA=;
        b=e0gqOk+ufG8B373flxmCVEryunCjMZSIMvkaaUaIETA97h+g8lPIXymZFU8O4GBao3
         7E1TFeweffgeHnuJMZ+ruhknyYm0/J5ahUDh4fX4UNo8ueHGGwZiv+9sUB1gkWatKMLS
         Is/1JS8OxQOPCZ81WoOhrBc1i8wSXPgjxDGXqO6h5TE9n8Yj8fp1b1dg8+9ZJmZAQF/E
         IkU1f7TKaDLCJkDYg7wtEdjOAS4a/EtzB8NmSpNSIrqPEtLxMQQNgfr//sIwocle7EIb
         HEeeB7vNXIcVHoBL2FIEz+DdS+2mMIitKeykbPj5rGkPL/1nvIMDul52s2mHdfCMTBaq
         5zlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=bwwQ7lsC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7009d5e51d4si65887a34.1.2024.06.21.10.55.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Jun 2024 10:55:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 49D4ECE3C33;
	Fri, 21 Jun 2024 17:55:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D2634C2BBFC;
	Fri, 21 Jun 2024 17:55:31 +0000 (UTC)
Date: Fri, 21 Jun 2024 10:55:31 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Alexander Potapenko
 <glider@google.com>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, Masami Hiramatsu
 <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, Steven Rostedt
 <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka
 <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry
 Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-s390@vger.kernel.org,
 linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle
 <svens@linux.ibm.com>
Subject: Re: [PATCH v7 00/38] kmsan: Enable on s390
Message-Id: <20240621105531.57736049ce642db59181eb06@linux-foundation.org>
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=bwwQ7lsC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 21 Jun 2024 13:34:44 +0200 Ilya Leoshkevich <iii@linux.ibm.com> wrote:

> v6 -> v7: Drop the ptdump patch.
>           All patches are reviewed.

I added v7 to mm.git (and hence linux-next).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621105531.57736049ce642db59181eb06%40linux-foundation.org.
