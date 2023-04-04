Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPP5V6QQMGQEBAKFASI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC8E06D5DB7
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 12:41:02 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id n9-20020a056e02100900b00325c9240af7sf21009258ilj.10
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 03:41:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680604861; cv=pass;
        d=google.com; s=arc-20160816;
        b=l5SLdDFb8zqmo7vr0D7/2PyLhJeemzDP2j46RYRgSwuNsnvVpuuRVitxGXeqSiB3hZ
         6Um+aDw5SQBCFxf+w/wUeFNI+++oJ+D3nYtINI2L10barYnHCLCL9zxUZhZZnBmDbTQu
         oL87FNaaknpj3Q6DlGovFsQEODsKwcgY4uviqnm9N4tFm3aDsSMWfPCpqY6WdPrQETwP
         W9WECqNjzKFOXqiESPIf/l7PPh2TT+lZd4Dn1utx+3fHnANJMja7GBmV4X1pvcR0sEdX
         Le9t9cwX8bB/MWnYgwUQGR1PUqncQhPJgNH2qSM2PlJtD7cJFkjjKUXoXhCs045pAidc
         O2jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ao4CYskd3fTsnYJWZT1JPAqK6peVsMn7VDXbCTLc090=;
        b=eRXClupEx3XDqQJ6xCbr9h5RpOuekRHGh5b6UIQBnYx+obbGNEH4nnF0KDWpI6rxBK
         ILj+MrUpLxkFZMgdbM+gOJ2rH7ZXBodhPK0EcPlz3IUIrWCV6ltJXvgpYLy/GRk1xeH2
         8z5CxQyaJnGDIa7EApOL71eZzu0iDPxw37QgC3tk6kcZ/1BpTzFFNkUAPOJerHzZwtA7
         NN09HoCwfNprZ9rY1Ii3FuPLMHrNCr4KdnJ6K4pyVZLIr9neJvMVGd6bfmjQZY3vejN6
         xONNJ6hTvyYpD7c1qXtmP32LXJLdJ1SIIHdcWbsfmBo0/UNBfpj7M+C3Agd7N+opqECR
         Q9ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SUFUspxs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680604861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ao4CYskd3fTsnYJWZT1JPAqK6peVsMn7VDXbCTLc090=;
        b=PvHylWm8kLjW0HkQ+PAXIjtquUJgbYJjSMtxRd+UPz8rIGQfArJJxavYTaWAwcTLeF
         JRnS31r5BCb3uKi57XOtifeJGfio9rcvtLLPUmZKbbL/bTjt0ysnr7CxU2EiJGVRvpWE
         7Edmqf18cWueJwt4PvzyWJ3xkJDHJWpfM4WVLoBTCYT2pPhmBP7oTVXxLNQRL0uSFbwz
         Z2O/56YwyLkP4S+SN2VhZza+nCuPJqKRZVLmX+nMUdkAmT1Ne7OEcvr29CSZa10TbUWz
         KjOddgzxHp8JtwfPvd03oUB01fQQ5UsVEKFiD0umfTYL10pei5ZZYNkUPueewdVYSfJP
         ha0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680604861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Ao4CYskd3fTsnYJWZT1JPAqK6peVsMn7VDXbCTLc090=;
        b=jjZaBugK5vh0tKaQq3vZnusNGQHacjSF4O1XFea84ByZl3JJhLz7KB0ocgc38bG1XQ
         7yWxgRMqoE71iVH7IbGml7aXYPgvSeP+Q0Xct/IV+ZDBQ9T5S+wyb9byMh8EmWKifr0I
         FeqSIf2qOM8fThGfMT9ReG2wLKoqgfHiZz3Alg/vF2F9y3d/LpoxDeNmsa6Q1J6FVQ6s
         R/WyTIE5+KFsIGMKuZQvB3Rbiqsfv1CQLZu01NqWHkGOXuihAY9Bu3IWbpkLyUgx1zZ/
         FsxJTE9uJnABc3IUDFkFlifmED7d4NjPtPqGj+1ahA84aKYm+hA8OHr7cPz+KDD/rPJI
         ReSw==
X-Gm-Message-State: AAQBX9ec3ijkITc/zfudfvTMcueHwjFivkJuXsZJIyi7/1iRnhFmn+Ro
	z0nPa5Ic2zgd4iGPAzkIEKY=
X-Google-Smtp-Source: AKy350YKwjWLxnKjlHvO7vnZiBrACizarEeEtHyrUks9ItYd8X7hB1ZZHdSgSTyPSzZa4XEfv1eehQ==
X-Received: by 2002:a5e:8815:0:b0:752:e3c4:41e1 with SMTP id l21-20020a5e8815000000b00752e3c441e1mr1271437ioj.3.1680604861534;
        Tue, 04 Apr 2023 03:41:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:160c:b0:317:979d:93b3 with SMTP id
 t12-20020a056e02160c00b00317979d93b3ls4489871ilu.9.-pod-prod-gmail; Tue, 04
 Apr 2023 03:41:00 -0700 (PDT)
X-Received: by 2002:a92:dacd:0:b0:325:e885:3d43 with SMTP id o13-20020a92dacd000000b00325e8853d43mr1574727ilq.30.1680604860444;
        Tue, 04 Apr 2023 03:41:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680604860; cv=none;
        d=google.com; s=arc-20160816;
        b=ebgr3zLUvJYPDA3av6sx0AcrG8aGqvk2AQ/23bOGsa9EWXQOKKUzKZRpE+cz1hb0FR
         soP0qNScvBtvctML3EALV9AeqaQMOlfuyFfvtR6D0Wv6zrQ91dkjgjKRi/P8SWIU8LJi
         7nTpKQw8CDHbpT+0Wud2bZLn08dAfvQKwodOPORgz579uX5AA61hzWQiRfLTMlxf+W7B
         gZzulROvkiSdOm7Sd3s7a8QPYOmjRSqeQECHFWfpqJrAL4fhVLjVCpWpSMyLLw67pkP9
         FQuEuZaxHswGyruBLbF5/v5ARmUdmpY8rEmZQUXTsiqr0p75zdq+DwZPtki83cqO+vgW
         vozQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iwzxcbPB4/3rI7150D2ESWEJjPWEtJtDQ2Zs7FQqEt0=;
        b=C2x9HEWrYonpzfCdxHhXAV6dWMmNmfq27e2As0Lc4d2J/PckaL7opoCQ0bMgRw9zb2
         WVr5yXPJ7YaiIhDH3eTn6GjZ5+GUwKha29WsaBaaq7m1QeVdbTW40jRJ03h1GRzcAfh5
         kHe+HFU69huRRg7iT4eLDFmyoSXAIrNhavXOEtJnpnp4G0d7iGDCnOHWjz1+33IYM1EI
         b7nVM6tHJG3m0JTVCJeqNovnFoMIfSTsorWco9BvLNQJHzUU1WdUHGvtyk0XIdA7qpOE
         1qKd9qmE9YPzc38woyOVEafH7ltvycXcOI/T3/18lqWFYNn00GqceNgX/8J1tYmp/GQG
         SSTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SUFUspxs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id q9-20020a0566380d0900b00409125e3b19si974587jaj.2.2023.04.04.03.41.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Apr 2023 03:41:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id cf7so38112259ybb.5
        for <kasan-dev@googlegroups.com>; Tue, 04 Apr 2023 03:41:00 -0700 (PDT)
X-Received: by 2002:a25:d0e:0:b0:990:b53f:933a with SMTP id
 14-20020a250d0e000000b00990b53f933amr2425696ybn.60.1680604859787; Tue, 04 Apr
 2023 03:40:59 -0700 (PDT)
MIME-Version: 1.0
References: <20230403122738.6006-1-zhangpeng.00@bytedance.com> <CAG_fn=UEah3DLYm2yKxBKg=L=Qc_PSnrKhZ2==snbw05XAtVZQ@mail.gmail.com>
In-Reply-To: <CAG_fn=UEah3DLYm2yKxBKg=L=Qc_PSnrKhZ2==snbw05XAtVZQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Apr 2023 12:40:23 +0200
Message-ID: <CAG_fn=VJwtnn8zu8oOZuG2rNUM46Rvz-36oEfVJiCsyeee8unA@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: Improve the performance of
 __kfence_alloc() and __kfence_free()
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SUFUspxs;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b34 as
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

> >
> >         /* Apply to left of object. */
> > -       for (addr = pageaddr; addr < meta->addr; addr++) {
> > -               if (!fn((u8 *)addr))
> > +       for (; meta->addr - addr >= sizeof(u64); addr += sizeof(u64)) {
> > +               if (unlikely(*((u64 *)addr) != KFENCE_CANARY_PATTERN_U64))
> >                         break;
> >         }
> I am confused. Right now this loop either runs from pageaddr to
> meta_addr if there's no corruption, or breaks at the first corrupted
> byte.
> Regardless of that, we are applying check_canary_byte() to every byte
> of that range in the following loop.
> Shouldn't the two be nested, like in the case of the canary bytes to
> the right of the object?
>
Please disregard my comment. This loop is fine, it just speeds up
finding the first corrupted byte.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVJwtnn8zu8oOZuG2rNUM46Rvz-36oEfVJiCsyeee8unA%40mail.gmail.com.
