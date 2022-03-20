Return-Path: <kasan-dev+bncBDW2JDUY5AORBN5R32IQMGQEFLX2Q7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 82E9B4E1DE4
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Mar 2022 22:12:24 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-2e6402f436csf4099177b3.3
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Mar 2022 14:12:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647810743; cv=pass;
        d=google.com; s=arc-20160816;
        b=EA8qxQjPnQXUt5nZ/rsq19NQhE8z94MHM2D9zu8Zxm7jbMg5f7sMpls+hR0zivA/pv
         hso6aW040SOj6BE2EBxuj9hLQ/bnui4r/0P9dOoMzb4lvfhIzEk0Z/CK6DgBUv0L93nn
         pdrHW6hzf6vyz7+aYijvPt5wrm3/foSL/cP+Pa3n2hN2U6OZLDce2jBa2PzRQDKa/st0
         +D2JxXqvgNSI5UWvGdne1iBYBPPiA6e13JkjuTyzq2leSPiz8K2TbDlG7hXlV1AR+ZzB
         OBR8ZPvMAQiBF+MOj2mv984RJrqjvr83PpkZlVq1eD8zjNRuNNOEKdEBmGk69uB8CQc4
         nNsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tZlnyfjkA0WumUMxSE9Hd+ZUwVkHDBSZT8c06i93zYs=;
        b=jK/VMnHQ2cZKj9FrkcEUiIoagSZhWMTFfaLG3caTuXqgjByiB8gGZXHQk+xiY/qq3u
         yZjEVs3WJhO13aOO8UoRb2cjS6cTmaQgdywBYlF8KgZssxlpEE98UwlXDOKFK6KzgBwn
         dRy99+ufAtTWBSCcFKdBxH9MN3ZivMHleRaNtRLgxFbTX7W1hL0uvaD1H+N/CXhQTEeV
         JTHYslYKM1HEBGRTQT1vMTdzLSpqo1xICtkab1tFAP8vXJlw341nCojye2uyvUL0Cjtc
         VRE2KUCOu0+FRyKK4VRhIXQ9v0+M/Krz2CVNYvPqnLBXn7kRO0tPEfqXx7bnct9Gf9Yh
         YTKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ElcsB4TY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tZlnyfjkA0WumUMxSE9Hd+ZUwVkHDBSZT8c06i93zYs=;
        b=nWn293Oe4fMeZvDzFpDTgNCq0BASW/vhVgxSVo1+bFGm3WW5Abh+Q2M/ZWQWAL5zwm
         gqoVfQfN/8Ve0VzcU4ENTlhyULpWjVwwubtuYrl1i+ueyHyqIsAQqAUiMvbLAku1nZap
         MJhsZd5OmEi7li+wNXM+Sy/VcSI1cD0vDjbgzg0brqZkX3w9vsfIcDb7XtHjHLyT/tc0
         FHvYc/VtVmAFq24hSEGZ8iitZrYv1w/kzGg6QAEhky+tmnAu8C3w1759d1SbRPIHS1wE
         u7LF13IVvrXm7gltUPf87rSKoaCKAQwuAidAShYoyCNfQ3udY9RwafyTHff/Tgz/WTND
         82jw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tZlnyfjkA0WumUMxSE9Hd+ZUwVkHDBSZT8c06i93zYs=;
        b=Pjdj4Wy5pdeDHduKcvlu+xqE4CAM21t96YlPnq/eVYI7HmziWggtCLNnTA9b4vA7Fh
         m5JABlL79ixEjJjPMYRZIpq9JL+MIQbo5ESlnFbcearnYYr4Ca9YGXJ+rbTf31iD30CW
         bSK+2yc2eHZOgTW9IPGnXwojiYBohQRimKnHXWeMUkC36IddYPLcHfqv8FJeLrPG19rh
         x3EI/pr1QHss0cg7XZmdkXINc9wqe4K40dVXFnJosNBUJLB9N0EOGi7aEhEaBUSuHTtB
         IUjkxv67rsT8xw4snQ/kqK9Vh6yBP2ylNmblnX0viWPVAW6piNo5ncOS+ClQe5CURffu
         Xh8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tZlnyfjkA0WumUMxSE9Hd+ZUwVkHDBSZT8c06i93zYs=;
        b=W4TbGMpbwYGASRbYUjJy867B5ow20nOC9uQeKSCJE8cMKNzQgk9U9SwCEixeFFI7Ie
         /+hJFVlv151/eC38xSpX1ApOk+Ki6DnMHU7V9R+RX+DtbIjQUODmngCbmDkbnO9rlrBN
         16VD1J3NrXypK3vnelnXI37q28P0DGSzW3FnJfsypnEV+b4JnmMzTuvAszzWlHLfSu8F
         5J2aD3he0dhYApSaw9EsA8bUDZ9DehR8rkbdB6F1yHeDHpsWhIarjjHTtq/fNR9GHCfs
         JyGApx+StuDK89uJnbTpxFrmHREDCmMHO/TsxwgWYgBlYns1lD9QEOSxEMJ3BrhmouVK
         FeHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325KS69MJnKGCi1I3S81dpzQZTCRdGv9DJdOsqf2hfViW92ID75
	LWbOoSKEFuzcMSPRF55WgL8=
X-Google-Smtp-Source: ABdhPJwVLXo9D+l2Uzyz0xxEXd9C6/kgedf7STKi7joQtsxeZ7P0OiZOOEnFIGJxnrsJowJZuC2pKg==
X-Received: by 2002:a25:1bc1:0:b0:623:2a4f:5d04 with SMTP id b184-20020a251bc1000000b006232a4f5d04mr19131045ybb.155.1647810743615;
        Sun, 20 Mar 2022 14:12:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a383:0:b0:627:f399:5124 with SMTP id e3-20020a25a383000000b00627f3995124ls10017948ybi.8.gmail;
 Sun, 20 Mar 2022 14:12:23 -0700 (PDT)
X-Received: by 2002:a25:358:0:b0:633:7a26:5ff4 with SMTP id 85-20020a250358000000b006337a265ff4mr18570546ybd.97.1647810743237;
        Sun, 20 Mar 2022 14:12:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647810743; cv=none;
        d=google.com; s=arc-20160816;
        b=liSGoHQ74imdFZ5ga8I7cz38Wgs5hnJKeT+X0SAOu+ovjjwlTPdy3e++vONpZysGJn
         XJVRy5orjNdmL3t/vBI1z8DcrnSqJzbOBC6AgUVnmNgUL27K0VLHyKSTDlV8eYzeyQJz
         PZAy4DZO5vmAlB2/FtHna8oWjg5OPUJnuWAfzeLRCkGx2fLEB7BCfDUVDB7TXjMIZN56
         N+l29WOtzb1SHBwc0OjGndhoNZpKS0EMEalD9DGaTkYkwfBZxRmptgmIYkodPfKYW5Z1
         YZvr1xDUcPMYfdu/vY8+v4mQcsXyrefbtll32kycHUXQxGPMNNnWefFuLkC4U5OPfIhf
         Rx5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yzq93xtEK5Ypv1Cyb7lhCiwNr/P453Ucxb4rl4WdV38=;
        b=0NtC72qJDHRxGl3dEJxRfrtcl5PfrjYhCI7FOrTK3L3LWMl+r3Z8NorEOlYYUfCxus
         iYT7qN4srsK2G8Urh0BH3mr8C0PloRtISKFxEhL+h2eiM63ASp30WLVUUqoY+tyMq7VC
         R+aSJXNFWxTcBY6vPHNbsVLMa1mcRDJN9NeFlMQaSKm1av6z3IRPXcKt6dRvtFojJ5pD
         7efqJ5kq/J8VezKQjyHOGYMlsj1i5udFh/3qVQtV0tCAyloWKPfupV2Dqp9ktrRNXFWN
         KcWhTpOHFdJAbCHzgJMzqcwdDXGZibtfNDHZ21V2R7KzLaBabTMBXJeA4BIGGEkbWBhQ
         UBIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ElcsB4TY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id r13-20020a255d0d000000b006332ac9b1ecsi885809ybb.1.2022.03.20.14.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Mar 2022 14:12:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id d62so14826664iog.13
        for <kasan-dev@googlegroups.com>; Sun, 20 Mar 2022 14:12:23 -0700 (PDT)
X-Received: by 2002:a05:6638:1351:b0:31a:299b:6d87 with SMTP id
 u17-20020a056638135100b0031a299b6d87mr9859261jad.22.1647810742908; Sun, 20
 Mar 2022 14:12:22 -0700 (PDT)
MIME-Version: 1.0
References: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
 <CA+fCnZe-zj8Xqi5ACz0FjRX92b5KnnP=qKCjEck0=mAjV0nohA@mail.gmail.com> <CANpmjNN-UPGOwkYWiOWX5DeSBWnYcobWb+M1ZyWMuSbzJQcFsg@mail.gmail.com>
In-Reply-To: <CANpmjNN-UPGOwkYWiOWX5DeSBWnYcobWb+M1ZyWMuSbzJQcFsg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 20 Mar 2022 22:12:12 +0100
Message-ID: <CA+fCnZc5Kz5AdttmbzC_Jj8=Q_yNz_iOoa9Jiu7trK8tVm+w4g@mail.gmail.com>
Subject: Re: [PATCH] kasan, scs: collect stack traces from shadow stack
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Florian Mayer <fmayer@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ElcsB4TY;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Mon, Mar 14, 2022 at 9:57 AM Marco Elver <elver@google.com> wrote:
>
> > Another option here is to instruct stack depot to get the stack from
> > the Shadow Call Stack. This would avoid copying the frames twice.
>
> Yes, I think a stack_depot_save_shadow() would be appropriate if it
> saves a copy.

Sounds good, will do in v2.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc5Kz5AdttmbzC_Jj8%3DQ_yNz_iOoa9Jiu7trK8tVm%2Bw4g%40mail.gmail.com.
