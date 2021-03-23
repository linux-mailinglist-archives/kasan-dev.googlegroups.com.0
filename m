Return-Path: <kasan-dev+bncBCMIZB7QWENRBHM542BAMGQEHFCUOGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E742E3457F2
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 07:45:50 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id m5sf1065050pgu.21
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 23:45:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616481949; cv=pass;
        d=google.com; s=arc-20160816;
        b=WHhuWY9olNp3VULnd4P//dJCodDnm/MaI4iPpph1XCDoh8KvjtptJLrmCTk4fpCgw3
         DhYXLWo4zI9zCkGPIpMhKKpTHJcTzO9lkZ3BrjMWTKf3T+0Metq0eUeslUHmr2jerpQQ
         19RUIcNe/H+AnJF7uLiGRGhSIAc4Xqo/j7FvzXzq+t/c7hF9XWjKNzEW9Yu4yG4fpFnX
         VPiP/gd2SnR3owcnlA/+MdK11pOQm28rbPhysn7lFRNdtQB1eeTz9N9w943F7amwxbp0
         PQ3QFhk93nUJDI4tQTUAN8PLx+utgQuYxLQ7tpp66q5xyr4z0GleEh+AeKdcMyroBOjd
         d3wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LlZt4O1nWTgSZBpu1nDcp3L2E/CTzy7+sEKsMgzzxDo=;
        b=oVY9Et7rb15mDNGIQ5m3iSJopizueQHllUjwsFY+LkhcekG6OiNBJqs7i2pjLcgrHQ
         AT4aJiEYDALrZH9uGFhWsYKhk+AdiP8ELH2HsLHt+jJdno2MeTlir1RUry/foz3ED1Fd
         sQjM3HHFBAj3kMW4PX29alRjO3BAR8OsWqsz7ugmY9bDxoEnxEc71xz869FYyP6TRwDp
         Aolw5+k7pquwiF9EApnIFypTBQIkJqoejJWDv4MdcgsbMNTFXHxJKodjR8Nw/USws64X
         /ssb5DMe+LxUlfxD8OO2eH+WBBu/CIY6GW10+R40E4VOYFuoU/zlkwISQ68Yf6NkYLOu
         UNxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cGqwhxSZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LlZt4O1nWTgSZBpu1nDcp3L2E/CTzy7+sEKsMgzzxDo=;
        b=KOpgSVjtm4h+YNIURNacexSABp1ljPLygt9X7p5nyDe0uanNcjWiCsIOQfYg0eQD5r
         O8KkW07TKMu/ODQzJ5nD6bC1YAbTDeI7spdAI2j6UnB9uKuuBYNePNL78+Lzc3W2tHTI
         5dYjDRAl3aj+KthFjFJ0//cZaPPSrYk0SZgHRzCJw138QtrHB0KkBp97adkJQKnwC7tj
         5/jLBBA+QlIPYyIzViQYwpVSNyY5NZ46vu0zySUQXuSFwN9Hxjz/03BwGBtLXhE+jLQg
         I0w8yCc/TgWLSr/m9R6rOCo43eUCTHAlSOBzf90B51eVoQh+EcGe3UAF/x8QDYMHiE94
         lkKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LlZt4O1nWTgSZBpu1nDcp3L2E/CTzy7+sEKsMgzzxDo=;
        b=WsKMkA+eXr3T4ae3xKCf4KWm735IAhNW1QmIxwmoxuW1MmFbxxy83y0AtSCoP9BcXk
         T7LiUJrT0ux5sRwO9RPPd1T3MNBwZwHjW73IiajgQg4rNFrAgk5HRl1aSMGNUfZh23Q2
         cjoe8Oi1FVm04TpDwBF4xSMJ9KkXS5f51lKRk1uYCFuRLcc1o7WCCiuoDS/1+pL7OmoD
         oVXQGlwqbuq09clWpf/bOj7BJI+YzdDi4hNaUFupxYtUcCRTZuru+8G3W/xQ6ojOLqNR
         gPryzcWQfajKCp2mbn0Eti7FzgQdmEMv37kZmd6ko/YtZlSjzTxWPyCB+mq2zbHDBjSE
         mLug==
X-Gm-Message-State: AOAM530qDGnNkPgTXXrTKxblGg5PvCbjKaqdb7OhBusOIYpD5fBXKzx6
	/wLWV47wV6jyzpWmidCRaaQ=
X-Google-Smtp-Source: ABdhPJzc19CSvd7zQIB/VjOAbR12Ut2ZafZaMghkkZj4hgdLkBVieoXb2ryRWuTBdC81iHA9s6WoHA==
X-Received: by 2002:a65:568d:: with SMTP id v13mr2827066pgs.35.1616481949388;
        Mon, 22 Mar 2021 23:45:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1417:: with SMTP id 23ls6434978pfu.9.gmail; Mon, 22 Mar
 2021 23:45:49 -0700 (PDT)
X-Received: by 2002:a62:5f83:0:b029:20e:70c3:c3e3 with SMTP id t125-20020a625f830000b029020e70c3c3e3mr3149975pfb.60.1616481948800;
        Mon, 22 Mar 2021 23:45:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616481948; cv=none;
        d=google.com; s=arc-20160816;
        b=pyaJ3UwQID+nnb09EUphm0nkGOpLw8hxJgdSgQVCVsWDtKcZKTx25icDy/aO86q9kd
         zpHYFRhKc9N4LClfwKc5scH1DJKlIn9n+AF/+XV9XzmZduR9YrxlxrZBOiBWFMqR/p49
         q9NM3Jc768TYf8a9f+2C5KXqlfKlyTDLTNeGBmFM2PZWGBqPGyUUbj2N/Vvaz78/j8HG
         8xNP9INiZLAuZPAnHmVdnt5F3xIDeN29IuPB4xcHPi1wxylq8ssgtg+B7cBQMTz5VBjb
         OTGknQu6A3qjRKWYOT38oUpkQGmRi00hDyOSQgKgGLqksAaFSW90PxGA438W+2JpYK7c
         j+Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d4wUVCs+q4yqVhvcyurU2/LdqdpYfVD9A/k7/oXDROI=;
        b=vtDyUSAnf+i7ab9XRpV7/kwR5k2oqiJHt5BkkC0ZaNRwvBpKlmDduHINO5FRGWen7z
         2WyWOvirFzwxCnGHCk0RBscQ2HW+EM+GhIs/mZKEOU1dzZSVEIQXuf1EhQlGXC177byP
         Oa+6WlmV3OQzwKNnWN/jav86NAF+bAfR49Jcd6R0x7bVy4UX+U0o3bHOKXnCmiDD9rVw
         Va1hBt4+AaeXJbtLL+dax+04DtQDIkzEJdhH8BDMkDCpzvUteYrYGl3KNDydDXzeEzkN
         0BN+ibWV5ahkv94qNl2UIRdfOrXmVC7BsbvZbcZxUAwOcXeZrgc0DPPHiUthT74ER+Iy
         1Wmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cGqwhxSZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id k21si1088502pfa.5.2021.03.22.23.45.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 23:45:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id u7so14205984qtq.12
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 23:45:48 -0700 (PDT)
X-Received: by 2002:ac8:6696:: with SMTP id d22mr3206970qtp.67.1616481947806;
 Mon, 22 Mar 2021 23:45:47 -0700 (PDT)
MIME-Version: 1.0
References: <20210323062303.19541-1-tl445047925@gmail.com>
In-Reply-To: <20210323062303.19541-1-tl445047925@gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Mar 2021 07:45:36 +0100
Message-ID: <CACT4Y+atQZKKQqdUrk-JvQNXaZCBHz0S_tSkFuOA+nkTS4eoHg@mail.gmail.com>
Subject: Re: [PATCH] kernel: kcov: fix a typo in comment
To: tl455047 <tl445047925@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cGqwhxSZ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::830
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Mar 23, 2021 at 7:24 AM tl455047 <tl445047925@gmail.com> wrote:
>
> Fixed a typo in comment.
>
> Signed-off-by: tl455047 <tl445047925@gmail.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

+Andrew, linux-mm as KCOV patches are generally merged into mm.

Thanks for the fix

> ---
>  kernel/kcov.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 80bfe71bbe13..6f59842f2caf 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -527,7 +527,7 @@ static int kcov_get_mode(unsigned long arg)
>
>  /*
>   * Fault in a lazily-faulted vmalloc area before it can be used by
> - * __santizer_cov_trace_pc(), to avoid recursion issues if any code on the
> + * __sanitizer_cov_trace_pc(), to avoid recursion issues if any code on the
>   * vmalloc fault handling path is instrumented.
>   */
>  static void kcov_fault_in_area(struct kcov *kcov)
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BatQZKKQqdUrk-JvQNXaZCBHz0S_tSkFuOA%2BnkTS4eoHg%40mail.gmail.com.
