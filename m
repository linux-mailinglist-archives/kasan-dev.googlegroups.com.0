Return-Path: <kasan-dev+bncBCT4XGV33UIBBLNC4KJAMGQEZLXGLTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id DB34C501D62
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 23:25:01 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id h65-20020a1c2144000000b0038e9ce3b29csf5115643wmh.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 14:25:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649971501; cv=pass;
        d=google.com; s=arc-20160816;
        b=ix094TWPyqAUDklBDduqHgHB3vvKJiLFqtFu5DKGuOQeGqgW6kFVotiGgiwwbhJO9z
         kuowWz8HEUvI6Imy1gM7FJIK7VMV1Vf8Z/UiQy4FROk0ntt0WlA4zrvUmQTNn1w5GIu/
         Zr+Z0NIgGd4BNILy6vKj3bPtgiIUKFzlAeVoAQiVBMtfN3lYD24XuMfp4ZrahaZmzCZ/
         /kvrgETG3XzkWCAULZGTDSPHYdbz27jTtQvu+pIX8lRFikB/ttviyc7mfUQ6ATtyCgCM
         ck0DyoKXaOGAhIa5oVKinvErP46XfXuVS8Bdiklx/R/GJlYusTjrKz8fbLuyv4lxsceS
         1VNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=+kKeATiiVwBmkxjY5/OUnIWDnH1EZGG9rB1uyciIK4A=;
        b=ztg8ejSHOFiKe9HHBOqpLSnZEZlmatqrnEtyFHKYurdGA1Rl2X4PDJ0woEZZ2rz+OZ
         OIta0moisnItrwAfpsm8rtUYRIcnaRTSZGdgrlyS8QEh6mD6u5cAYW2gqQSFuuVra+o+
         37V01CiWh8o1/O0hJik7H85lBniST4sIv1BK5FHK+cCClXWZrx67fAJ+NF2np8AWm0N7
         +91QHlJBjcBN3bHAwnqV6EUSDnHnvXk1BnMA5Ik8seQ5+AnyiEYiIiVUKY8zj3OWOC7Y
         RTr8rYQlL4EAiPKz/5TvEcLYT0j+9zI0j8ZbzPrSwVlzfUYNbfzebH5H88wbhrxnZ13E
         uY+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="Y/4dWiF0";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+kKeATiiVwBmkxjY5/OUnIWDnH1EZGG9rB1uyciIK4A=;
        b=rtUC80Xg1/aFVGITaz+BHi8/JY1lpJoW4wc2rIjmwwf7/VDLStsv22l7eIRtcxWGxD
         SmFfZK7CRW2NlznAhfT9FPsObCORNtKCVO4wjCopmcseFlHPdx4BqqF71mbaBQfloGAe
         0Ic7ondAvbZbE1Pqjgy8kfTHQYwkEYGrm6eM8shAi5H8gftahWeJofnv8eKUOp1J/cDQ
         ENK8iAIXGAKXyyEDJdW4bXThJ2a/M8w/q62r3L4LfDjG6aS+khvJqe1mVHuvZdIZa1Kg
         mgUMnF2fIZlmxmI+Dtv3O/rJ9FH9q5HocFDAsKTTYZKVFL2+R0Ubq3tTJfF54Z3gZ9eU
         dkFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+kKeATiiVwBmkxjY5/OUnIWDnH1EZGG9rB1uyciIK4A=;
        b=Q1PH/+NheGHkzEDHXKwkZg+/b1/nw+4ZXZYo+e3KpIaxa9j4ou/2tZLcprPASx99KK
         jgeWDQTbaAgPWRAOc28JCy79S9MkWj/V3MH9hzNkPVW1KkB595fW+dK7RiTPN4eu4RrR
         LULdRvQbPEG8lhDra7N6Jpe0N04mU5E0gxc0g4iCoXJv8pGRzP2vt4Glb3DGmwWTG6zb
         BDPoX6zxje3qJTnf4AuM/a8KvKBv64wdS9/AdLKtg96bPwYNZ8EQPPakvq7yzfIxGyUM
         jfpWt0lbiEAjldvyRIFlbNz6CW4cKKXSTASb6xuqjGlhFuaYZQ2QuQwahIjKFYCs6hdX
         2CxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tny3/CU6Vu4bHOr5UvefFQY+hjamknIFRyniBThyR/N0KCKPr
	xcYKG/Ce66LwRGUNiTjOyjs=
X-Google-Smtp-Source: ABdhPJylopnyPXWRENpda6WMAaSm/Ka2SyR2YpgXdpbAv2OVbm4e921b5q4otJm+j/dwNGcqjLgAHg==
X-Received: by 2002:adf:ff8d:0:b0:207:a0e2:4487 with SMTP id j13-20020adfff8d000000b00207a0e24487mr3377962wrr.570.1649971501542;
        Thu, 14 Apr 2022 14:25:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f950:0:b0:205:dbf5:72d8 with SMTP id q16-20020adff950000000b00205dbf572d8ls1760868wrr.0.gmail;
 Thu, 14 Apr 2022 14:25:00 -0700 (PDT)
X-Received: by 2002:a5d:528b:0:b0:203:d928:834c with SMTP id c11-20020a5d528b000000b00203d928834cmr3404336wrv.500.1649971500366;
        Thu, 14 Apr 2022 14:25:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649971500; cv=none;
        d=google.com; s=arc-20160816;
        b=Ymiu9ktzsHi5HWIXnr4OZu71QTcdOXEbuWp6uVTwrPWO8mndFmloww2w+RvurJTJ2F
         eLmgkrW1ESeM4QzxSmBAZoN3pe6F4tJG/AzsVyDQs9+Bw9A0KD7UxOEIYGXvAwDeaQs1
         OJXqESPSoSuUzrEwyG/iglyUPlUtbyT18uSi4BR9WSEb+1d7vcUQKtUVr3uX8MAY1uM8
         9hlQ85nUMJeAWB/PSTLIKyuq0xypUpLxGvnsAptu8Ki7vAij3HJTM1oDenFp4NrPkUC7
         AZQqIUiDYBP8TFq10LKsU4Qkf4NkuxR3Ud/SEY8CWFUZldE0Xpqpo0f4NJveh30q1udN
         oJCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LvxHOjjPSqDfEIERe8vY9wM8Pb/QDf7DRQ3tKHSDPtE=;
        b=Dln9JuMwuBSCaobDd5agibt69sRLvmwsP5LCUYeU1A/96xXVTsVjH678tc77qpSClr
         xa7+e0Z+mpSwDgfLw1oZSvkMspgkZDGAk+HcUCYGIihwqD3h2sXgHg6zZNQkf4p3CMAl
         NXcCb9zDoDEJBdAdUFZKSvCZ+X29pmuYhlqOSI5CrMz/Pt4wDF+7EvChQnjorgRAiHWf
         xr756Ji42HLCA2/eUSlgu6EnAqy7N2jp2JPhS69TKb+yK46y/u2rbqLWX7Bf8ENVzB1d
         zXQ8LdP/w6ukrRzQutCzVJEwqn71BNn9yPQh/PzjYQjbE71OmCacjykkZ0g1N0++WYl1
         19pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="Y/4dWiF0";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bh5-20020a05600c3d0500b0038dbb60f155si302wmb.1.2022.04.14.14.25.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Apr 2022 14:25:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 0776FB82BB2;
	Thu, 14 Apr 2022 21:25:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 613D2C385A5;
	Thu, 14 Apr 2022 21:24:58 +0000 (UTC)
Date: Thu, 14 Apr 2022 14:24:57 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 dvyukov@google.com, andreyknvl@gmail.com, elver@google.com,
 glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de
Subject: Re: [PATCH v3] kcov: don't generate a warning on vm_insert_page()'s
 failure
Message-Id: <20220414142457.d22ce3a11920dc943001d737@linux-foundation.org>
In-Reply-To: <20220401182512.249282-1-nogikh@google.com>
References: <20220401182512.249282-1-nogikh@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="Y/4dWiF0";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri,  1 Apr 2022 18:25:12 +0000 Aleksandr Nogikh <nogikh@google.com> wrote:

> vm_insert_page()'s failure is not an unexpected condition, so don't do
> WARN_ONCE() in such a case.
> 
> Instead, print a kernel message and just return an error code.

(hm, I thought I asked this before but I can't find it)

Under what circumstances will this failure occur?

Why do we emit a message at all?  What action can the user take upon
seeing the message?

Do we have a Fixes: for this?

From the info provided thus far I'm unable to determine whether a
-stable backport is needed.  What are your thoughts on this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220414142457.d22ce3a11920dc943001d737%40linux-foundation.org.
