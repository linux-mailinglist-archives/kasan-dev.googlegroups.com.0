Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVM5V6RAMGQELD2J7JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B96756F19F4
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Apr 2023 15:49:10 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-6a63afc70b5sf5320461a34.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Apr 2023 06:49:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682689749; cv=pass;
        d=google.com; s=arc-20160816;
        b=JA2JDMEefkeNbpX3khDoKdWcu1lxtEL+1MnI6YQxTH1kyereDps8/qHc71N9fnKhjp
         MixRaHtaXb/xfcSYuTfaGXDBldopg4bqURLdV3a9Daxd1IQcBpUx1F8yeW4nt7gMpnUJ
         Pq3jVnK6zjOkHAyoB1soKSHLuIqHne7veQ/oFKA2NY6TRHvVA9GlMoMRsur2SSmn3VQA
         CWYZz68Siwx1zRU26J2p3VpyHx3kIiDGVfuYvY0xMF83UmtDTNkmgrNFyQ3byAMOHlxj
         kLe1WGe/aC29k1eGJqLIg97nOovJGAMvWxeFLbdDLdNNAvTrx2/MF34dbSe/2N5MK2kM
         OKSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=51BmeHjH/3CpmqFBQoWFviRhS+5iQQCTCWis1ZqKR5o=;
        b=o00fKLzkxJeR3qKA12BmwuSQy/Kp91uiXmC9YYm11hYdscCi83z97GsagRYAWfRKwM
         d04+sy6WbfX8I3xdmpHTdQC00/fLGEE+j7vvHD8bcZi2WglT86RU17xYRa4w7ZANrNQJ
         5a6xOkqDyUcYRADXU9g9rSgOc9okKZsAyi4mp0jfNBUDPx8mKsm0W0i6KWUrTTedYsxP
         eACoeZoHOQWpd1AQEgyGn3RVWh+qdNg7DRXgfhfyC41Ifn515m6ps7wMEu8a8gbwgtCI
         MraI4LTVkGooi23dR3VuKevhtlDygNw6Xrw5Y7EuDZHtRiBa2nOd4bQJM7csIfesbOnY
         xlrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=f3+M7QDL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682689749; x=1685281749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=51BmeHjH/3CpmqFBQoWFviRhS+5iQQCTCWis1ZqKR5o=;
        b=FaZ/yYwlDMxQ1cI6vDx5RkTYEX6R0PzXoWP9xrPbCpnf2Wzc5KRmaSQxG87m6MdULi
         O45Pr6KXd13wLtZuWyQot89NX2L4q+YD8MPOYBh1qvgSeyYQw7AES3hTPAt+tdvlDRRh
         BxbWFiMvSXvqnVYVXYdmKH+BavsvU+K77TqYr1NJjp8EfwUUk4uvBsGEl9Mb54L8e/o6
         gLeiS7Bs1Anw7um1mWUwLYDopxci4kTyDxOEdi82u4xKuVpLdArZ8zTpAExbPESMdO45
         f8Wmpe/N9tXTXSaaGRSraLWFTSDQUMZSiYznmCua5ZB5IVMEG+cmHu0SRGidCnkMegPk
         tAnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682689749; x=1685281749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=51BmeHjH/3CpmqFBQoWFviRhS+5iQQCTCWis1ZqKR5o=;
        b=F9mmuhdX2Y3FbrvAeonhITAPIdubcr828K5GsJJmD3/jWsivPJsOj7mX/j3FNQNoXr
         HM7pI48uJRRGoWgi5qQOOp52FvKfr1Ie2TGK56Exh8K995OIZ9ShJUfTcY8ftvh5HD1F
         QyLEEu1BWeEfRaUkWUJVG+T5ZQck+JqES2sVP1jiFCELbRuR7nmvZkmS2wrgnotmP7w0
         hdJ6iGFyQNoLZmpBD0SttP5RZ5nU/GixgPSNkbhqdTyMRHM/FbQQHUHuXaWN6ZYbu4Ux
         K+UMuQnJNNTq5pGX3U+1WrPycqqLZwojN4fTAq26l1CPTzoQFvgIOdn6OKPMOVkHWcID
         MCdw==
X-Gm-Message-State: AC+VfDzlax0KHbuOqNzv8cYiecuQsnyQ2UxLg1u/BGRQBNKYBpYVjk7S
	wGxs/2fDlQA7S4ot6cVdVEI=
X-Google-Smtp-Source: ACHHUZ5XGLnytcXFm37OJjZE3KobuQfUfUgatQABS61yHkzNAgZ57Z4TrByEzQ2Y1vmqzEUFCR1UwA==
X-Received: by 2002:a05:6830:20c9:b0:69f:bb3:2163 with SMTP id z9-20020a05683020c900b0069f0bb32163mr1437580otq.3.1682689749332;
        Fri, 28 Apr 2023 06:49:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4492:b0:18f:36e0:145d with SMTP id
 ne18-20020a056871449200b0018f36e0145dls751629oab.3.-pod-prod-gmail; Fri, 28
 Apr 2023 06:49:08 -0700 (PDT)
X-Received: by 2002:a05:6870:a4c3:b0:187:dcd2:8da3 with SMTP id k3-20020a056870a4c300b00187dcd28da3mr2423827oal.24.1682689748688;
        Fri, 28 Apr 2023 06:49:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682689748; cv=none;
        d=google.com; s=arc-20160816;
        b=kWq0a+Vx1IpdVpwU7itRGfv4HlPABRos0umZi12gFBlS6rFgA4mHcfvYzFGexwuJFx
         D5rvjzBP1bRxhzbGjl9Csu40WPFYzx3Zdfp+uBxs8UpDeGLKV2bdMF/NpmhhyG75s7kV
         Z9R0Zp6bkwZgfRz2A28y4fJ1VNLK/N07g2Y6CaKsWkG8ty1F1fS0SaVpm+XlnwLYPs1y
         5nFg57iUi+bmOGVoJ0D7UMHW8cNXXpObbwgjIHvAe2tBaZwbH43WqJnefXedTQysL53F
         aaaFoYphKycTAFxZJNi6oyQDy8kHxiq/x6PJEfLyVo/kRNba+4s4XkjAx4Ez2bMtL9vk
         dQEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K1hIAJ3PDs1STD5Nf5EOLfCuqukCGdV5NWCw8Nh61NE=;
        b=SezAFw3TQKdvgP8Of5ZRXcFgGFc0ofNNemhzQCtKTimJpRxLMHVQPyS+sMzcwygkzD
         0CXIe1ElVb3NBffH3LuJAiwnu0Y5iqcDsNc0iZt+zxnVVLN1iK+aXpHLa8Xocyoxz+To
         GjTu8n/rowl9s3ur1PYdMnMTVpB6Q5JxW8nJB3TVZ50BNtv0Q+g5g3K3e3vbMG6tSvAo
         OsIoslYkL92iXgAzec0d07oewXhntQ6r44zRN8CTITBAuSlWtSBc6t1yFAs3XeMK9Up2
         D1EjWH2CLxmLiShnDynDwj9qqDfIxq0KZKBEkcmhghzU6/vUXncOBKYxwNiVxHCuN2Bp
         G8eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=f3+M7QDL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id g6-20020a056870d20600b001840f14094asi1569616oac.2.2023.04.28.06.49.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Apr 2023 06:49:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-b9a6d9dcbebso1994160276.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Apr 2023 06:49:08 -0700 (PDT)
X-Received: by 2002:a25:2843:0:b0:b9a:38b2:8067 with SMTP id
 o64-20020a252843000000b00b9a38b28067mr3442325ybo.12.1682689748091; Fri, 28
 Apr 2023 06:49:08 -0700 (PDT)
MIME-Version: 1.0
References: <20230424112313.3408363-1-glider@google.com> <6446ad55.170a0220.c82cd.cedc@mx.google.com>
In-Reply-To: <6446ad55.170a0220.c82cd.cedc@mx.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Apr 2023 15:48:28 +0200
Message-ID: <CAG_fn=UzQ-jnQrxzvLE6EV37zSVCOGPmsVTxyfp1wXzBir4vAg@mail.gmail.com>
Subject: Re: [PATCH] string: use __builtin_memcpy() in strlcpy/strlcat
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com, andy@kernel.org, ndesaulniers@google.com, 
	nathan@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=f3+M7QDL;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as
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

>
> I *think* this isn't a problem for CONFIG_FORTIFY, since these will be
> replaced and checked separately -- but it still seems strange that you
> need to explicitly use __builtin_memcpy.
>
> Does this end up changing fortify coverage?

Is fortify relevant here? Note that the whole file is compiled with
__NO_FORTIFY.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUzQ-jnQrxzvLE6EV37zSVCOGPmsVTxyfp1wXzBir4vAg%40mail.gmail.com.
