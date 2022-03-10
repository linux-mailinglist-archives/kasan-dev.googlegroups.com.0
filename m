Return-Path: <kasan-dev+bncBCA2BG6MWAHBB6PEU2IQMGQEMUTY37Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 92B784D423F
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 09:10:34 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id v5-20020a2ea605000000b00246322afc8csf1979150ljp.4
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 00:10:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646899834; cv=pass;
        d=google.com; s=arc-20160816;
        b=rtkpxyab9FGORPgKftG0nC+LonDZ7K8qWGfgqy6O0vFQz0dnI9cKUevrs4I/RYn/YX
         PE0fEJFUYzn3SwcJNaDQTGy0i9Ooh+87YCC6uhS+watnbV+XI+y8S0msuIP55vWaKnkU
         0zWTufBaahVVUwzLQEJuFAGyg3WHyMiHneCOATLj/CLPkwfIXNr2mM3pUcV9h26tnNyN
         9/vRd7PaFHdZhocH0tR0JMB0MBiUw1De7cOt+4evtrrVh5Gtx5Xhynf8WOwngUfOepyg
         HqguXUwXLOOcIo1ECSyccHkao2m4GBTmiFYqFBzQILQxcUec/uszmFL2rieH1u6MvU/u
         Hkaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VniN4Excho/LNoZvuXtKSksxn/1CbqrzE+UXkBAhrQU=;
        b=CGLc6uiI4vCrfNMZKMPdG81fJnB44DIPQ+FyrooQDAtPxnEaesb8RNltd8BkeK9Nrq
         Si5CNEUM4UgrD1UenQG0y7ACiagE0267IOQ7pLIMaOYKluC0fhfxtVcpbD32EWB7gfSe
         NSpMJvVEq97jdRvhzmiCryvqKNGpn8F0S6QGU7Y1bomtEs/88EfelJ61NwCKbHX1047H
         /c9ubnSg3nmrDC4rdwKvJOaMAndbyxhSbe64qhkL4kU67sxDfLB5grw02OaBD5rtyjkG
         enycsgANVOAWB7yi+OlVHkNeCCMaPDYi6x7WsBRn5vTotWFJDqN1C3heIgIiZq7P97W6
         nvPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gPCSxtOt;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VniN4Excho/LNoZvuXtKSksxn/1CbqrzE+UXkBAhrQU=;
        b=Oq1Q9tj9wCE6f2P95gWmnMavS+sNPhzbeeJYbUeDZyTojAIVa7knq1J6kce/jkDmNP
         iBWrqu1OCJW2ecZKKe2WgzRH4IgFHa7jCBgEUZmElappYJa+LngWrAbU7US8XYdSo6BP
         TFNcQcHUjXrK1MWdU3GW1HZ8pmrkjtyuKo7+9WmoafosyFWFlu8c8S7tQ2MSvBsD1VD6
         E0AEBk4yWs6U5N6H1wpkXWKbpEVryiRuDV+E1jM7VVPUje/NLphAGc4Oz1bJF4O+JQAk
         xYRLAx1sh+8mf06CUnafoHfWBYA5VAqe+K+xwTeTz5Yc0sTXOAmc6wyFAX++gP/464D9
         /kkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VniN4Excho/LNoZvuXtKSksxn/1CbqrzE+UXkBAhrQU=;
        b=Ie4aIuThrfu04lS9g0pU648L0PkbID3soxsE+6gtok8f4c45Tk+T4FMw+ZYnf+TCvr
         9ULL3ZHVFtv3OdNDXSDGYn4EN9sy0V9wbqOtJFsyYw2G87PgBOGjaDxtzJjBsYm/jwl8
         ydC0tOUlksNOdoevFfPabmUuO1OOOMYTb959ZZmSA3P4RDbLPy4A/I9JlMQrunUqMJB7
         lo4x10XbT1mC43auMHGFIsWg9QSYDUi5ZagfpO1llfN30apIJufVIpuaorkarvrroyBD
         hBgkydr/OI/lKN9Idbt+fVNl35ByDCP9EPF2uiYSMdd6c9qvaS7xzzEEqFzQFMIGLhOI
         Zl4Q==
X-Gm-Message-State: AOAM530F0gMgGNwN5bfF3hdez22++XeeDuzGLTMmLuDMYt/0XC1zfySg
	adCFjneMkmt7+4aXFQJSgqc=
X-Google-Smtp-Source: ABdhPJyNzrAJNMzxkaKPekTMNQ7R1RKSK1L6YzmJ2zBgVEMbL3U+8fj+CoqTe6Wb/HAhTkLf2Z6jGg==
X-Received: by 2002:a05:6512:ac3:b0:443:d3e3:db0a with SMTP id n3-20020a0565120ac300b00443d3e3db0amr2330585lfu.298.1646899833973;
        Thu, 10 Mar 2022 00:10:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b05:b0:448:696a:ea62 with SMTP id
 w5-20020a0565120b0500b00448696aea62ls237839lfu.0.gmail; Thu, 10 Mar 2022
 00:10:33 -0800 (PST)
X-Received: by 2002:a05:6512:2147:b0:448:35d2:6093 with SMTP id s7-20020a056512214700b0044835d26093mr2249688lfr.328.1646899833035;
        Thu, 10 Mar 2022 00:10:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646899833; cv=none;
        d=google.com; s=arc-20160816;
        b=iLqpyW8lS81mJOaZ/MMkTLk2HUrHlLZOfLwIG7/OpfT/AVVWoobr1D+D24KwmC4p+E
         E4XlOBIglUyaY0jXmqbxOeMunwDbB6NoXaXhhoQb3wTX2CzpJcelSaSNbJcjF6ekabFX
         4oMdBPSJUrdftiEN+jruFT1nqjNDFzVFjvtsBnzc10BU6czuZs4dI0FfA94LZVsUgWw9
         IDaVvc99hFeBcLVNgmp9Ft6KaDTFxbPvB9pRk26HV3/ZxLl2U7JNJzNZfJwOU6XKLPUk
         8MT9f/QHTKFZ9d/5xOtzee73hLeslYJnLl7GvgyKFgrU6jQdyVDNAI2Qv/VSlXp+Qsgi
         u9gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ig5zBgV9456yZCmUhF8sBV7DGvRjdoa/kYWf35qIWfM=;
        b=R5RozGezDeg2C1vFNiwziGOFkxyhYplGpWsZ2We65YF5420C6zhw+TCr48WDz6d037
         15u518+jcZ6pfoezFq/VHDPNp1lUMEqsDKduJjSxYHHLVuQeg+wEdEM5aZJ4hBBC15xU
         FNRHMX07yQLjQ29yoQuSZH3AMaxw7/Goquu4BUUHAbf4wkRCDlnMycWFYHdU7q+Rc5kn
         5nU5CXhX41Hmc5sdh9PuUXdtkq58AXKl9A5RdiVFnH7QDKGp2Lbs2W6D4OXjPfQfFIR9
         0ZlNGA9bftELzKq+GvTa+ahJG3OQFDBdWH1tnDsQLm5VSFiVEBlDYwPG0SyZl4fY3XpB
         zwrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gPCSxtOt;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id g7-20020a2ea4a7000000b00248059c8612si249740ljm.3.2022.03.10.00.10.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Mar 2022 00:10:33 -0800 (PST)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id qt6so10248440ejb.11
        for <kasan-dev@googlegroups.com>; Thu, 10 Mar 2022 00:10:33 -0800 (PST)
X-Received: by 2002:a17:906:2899:b0:6d6:e479:1fe2 with SMTP id
 o25-20020a170906289900b006d6e4791fe2mr3156352ejd.394.1646899832564; Thu, 10
 Mar 2022 00:10:32 -0800 (PST)
MIME-Version: 1.0
References: <20220309083753.1561921-1-liupeng256@huawei.com> <20220309083753.1561921-3-liupeng256@huawei.com>
In-Reply-To: <20220309083753.1561921-3-liupeng256@huawei.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Mar 2022 03:10:21 -0500
Message-ID: <CAFd5g44MbyK1Dg1yc=tMys_GPri+kjLO+2Kahv0rYEcp=+JP0A@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kunit: make kunit_test_timeout compatible with comment
To: Peng Liu <liupeng256@huawei.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gPCSxtOt;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Wed, Mar 9, 2022 at 3:19 AM 'Peng Liu' via KUnit Development
<kunit-dev@googlegroups.com> wrote:
>
> In function kunit_test_timeout, it is declared "300 * MSEC_PER_SEC"
> represent 5min. However, it is wrong when dealing with arm64 whose
> default HZ = 250, or some other situations. Use msecs_to_jiffies to
> fix this, and kunit_test_timeout will work as desired.
>
> Fixes: 5f3e06208920 ("kunit: test: add support for test abort")
> Signed-off-by: Peng Liu <liupeng256@huawei.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44MbyK1Dg1yc%3DtMys_GPri%2BkjLO%2B2Kahv0rYEcp%3D%2BJP0A%40mail.gmail.com.
