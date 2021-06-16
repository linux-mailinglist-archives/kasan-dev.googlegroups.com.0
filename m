Return-Path: <kasan-dev+bncBDQ27FVWWUFRBR6UU2DAMGQER5UCZZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A263C3A942A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 09:37:44 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id z6-20020a92cd060000b02901eb52fdfd60sf1107332iln.14
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 00:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623829063; cv=pass;
        d=google.com; s=arc-20160816;
        b=zBpEjojVs+9FGitHCf9iCNT02vFkPscsn15Gft4ZoDK7/889T/BckfNSbUeXo6m79V
         eUKW6Kev9c13ntpp76yxkcohsGYa6UmtK2O6RDQylLfOQgwIJMPP29ltaOcbP13MuHWb
         2nBegNf9wkklyrR1vTG5IkAUEuI8JGSkZIt+1H8b87oJe+nUz1SzSJ39d1nMop/wFEKr
         hB8oaUBFpJ2qGq/5Z9JnAmxp32o44Pg9WBrKg91E8nfE/tVhNyuIBpJBnB3RgsvNYzGr
         gosoc8T7lbUXlBsYY5+h98bYQ+CkEYsnQ6637PvZFcmsl2Zo94nOp4XVI52A7GngwMiI
         SMvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=yDlWkgDfiSGorkqtFOfXHTRnXH1/gSDO+DKVAcsFPiI=;
        b=X3Y5lTZCgOUQryCblVOwlYRCxzHTtVlbG1iA5QB+kb4VkLCwecntIHWU7gSYg1z7OR
         cmWJdA+CG7R0dS5q8N7T9DG4PtCAeiPXMAi5lwGVK/YxCcJgLge6WneTGSFZ+2mxVsgg
         vzxwdegooZFr0XCTUwf9AjFH7OW+tSa9UkGsevxzrEAgbchJUOei9q04S1f435oaLUMb
         cYHHsrZo8RtjrG5gQB7m+Ub4xfntUDHJ+95my1Fhu2mxKPPwhGQPDLzVRHlWOjqgjxG1
         y5ea8c4dp7hKYoinR7jGHErCxjtbC4Ny+DctG3UtahSPuTZw3NjNtI8qYdH+q71IITEj
         P7mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gKIuU89m;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yDlWkgDfiSGorkqtFOfXHTRnXH1/gSDO+DKVAcsFPiI=;
        b=FfbFTmYVoR4K/JDbkz6Jxe1y0Ck5V3HU3ujKccqge8icjESPz6IC0bxidcXQZNx22k
         fSYAu4KVNbhNY5ToHacIuPkJmHaeVTNjZleFsI5KZIQMLl5jAP3lAFRJb0aG2yvfXLk2
         UTu2ZvL1eg3/8vwqv/We/TYRZMPQ4OU49kSETzIMl7q5HyK8zYaGhGyIguWMbqiXGq5w
         7KNaQalnv3PRmC6wTWuNQLq2ik+5zdXs/40Y7bewmadGoDMVqr8JmxlPbu74UOYbo/3+
         657ap+HVoi1Xi8kKESca5IwM9Le5uLjh1yZuJSZ1qEWqy6G1NDBA4fJELqO9aykPI8D3
         c+nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yDlWkgDfiSGorkqtFOfXHTRnXH1/gSDO+DKVAcsFPiI=;
        b=sVo8wjrVKLk1PG3vxMM7jT0qNTs34QQ9fzn59Q8BAPw1CL2bt+kcfza4W/GLZkdWjA
         yayeE+eUXtE2YXlTQp1aDDM0EBVnncSwcbs/boOqifyOpSWkDXjg85wAJLOwWzw93Won
         kreBt4CSO2spNrpyxVTNKx8oeCo6sq0zy34YkIa947BFaRvl6wztSpyp++Pu1hO2qHUx
         IYsRdptOU8iGB+33Bm7cT7hW09lsU+eYPfLB7bj7IKuZDnad8FkAkEHje7sUdaLJFoas
         2zgDceBILdw98VxxKb2vo7RIw1MrKG5apknvoX6P8TSBmqisVV3XNtnRM/0AAqZWodBf
         ob5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ThykLBo9Jg2baG6W8uRYAtJGXvqpk6iGUiASllDNuOlraitcN
	S/S1/KTW+pc5Agp8TeOloZo=
X-Google-Smtp-Source: ABdhPJye499wrVLLoMOubtwATwMeyUi9JJQKGCScN/3QewAHbWMLsRur8AYO9jkvQiU48IZozPqz3Q==
X-Received: by 2002:a92:cb91:: with SMTP id z17mr2895063ilo.31.1623829063256;
        Wed, 16 Jun 2021 00:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1201:: with SMTP id a1ls305036ilq.11.gmail; Wed, 16
 Jun 2021 00:37:42 -0700 (PDT)
X-Received: by 2002:a05:6e02:218e:: with SMTP id j14mr2717350ila.81.1623829062915;
        Wed, 16 Jun 2021 00:37:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623829062; cv=none;
        d=google.com; s=arc-20160816;
        b=fX+tNJGr26sx4SWAqvv3osmU/SjMdR+ZG8+kpxBqjTNK2smkvWIe7EWZ1f8W0SY6s1
         HIH7+A2PmMYHyJg4f4eXvhORIo08ARbPVrKx/arEGAODNEBxHWuXDzAnmoIwbj0FjrWL
         1S8REIGsLIFBb5/ILDSM1ErrPUMpgcqJIAXrtW9OPh/V8AlnomL9y4Dz9Nnjeb1AVAkz
         JAzr6Qj3WHQG8LaopgjB717mdSWNeDp+mtB+YNCvNovdEj0qenCqSxjx1YImH3SuyB1Y
         LAtST6ZUKYHDm0oAUxD8gfilzBcvwXYJMfaRg3APRg7hQ4HpedwNR5INwHO2UVjVZmCC
         GBYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=evSxdOM1nOwbHAfBjsVJg+/nVzrG48G768sevWXgaxs=;
        b=Itobm4MwHANFBGm1l95OhOKXQeQwAFsCIUeHKM/ehlOSlq36gxdlZrPU7mjDSlmkX1
         o237agy2h3kgpyrrWO4VBBEeh3aTo650uPUI2L86PvgnqrKCBETo+HZgWf98uxackSQx
         TyTHmc+X0WO+8dXUjxwkyLrhM0eQNGtRy7KmW5xteFMHVxeB1Vyq4X6hi1EZ2GEQYNXv
         ao0DS9Xpi9fVb4Wc8Gyf978bUs76vZo/G0zHzck2cDq9fWYiixhsblE/SGMfHBNdVYe2
         HXci+ohkM2PPW4+uySLEyciI4g8K6IKkpKmDMODnhI1sT1A9nBtHe3q/xZGzy8stztTX
         eyUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gKIuU89m;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id y14si95804ill.2.2021.06.16.00.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 00:37:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id t9so1270064pgn.4
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 00:37:42 -0700 (PDT)
X-Received: by 2002:a62:2942:0:b029:2f4:e012:fb23 with SMTP id p63-20020a6229420000b02902f4e012fb23mr8275605pfp.55.1623829062244;
        Wed, 16 Jun 2021 00:37:42 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id u125sm1234914pfu.95.2021.06.16.00.37.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 00:37:41 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: bugzilla-daemon@bugzilla.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [Bug 213335] KASAN: vmalloc_oob KUnit test fails
In-Reply-To: <bug-213335-199747-KrQkhYd73d@https.bugzilla.kernel.org/>
References: <bug-213335-199747@https.bugzilla.kernel.org/>
 <bug-213335-199747-KrQkhYd73d@https.bugzilla.kernel.org/>
Date: Wed, 16 Jun 2021 17:37:37 +1000
Message-ID: <87czsmuuny.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=gKIuU89m;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52f as
 permitted sender) smtp.mailfrom=dja@axtens.net
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


> I bisected this to 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings").
> Haven't yet looked into what the issue is.

Thanks for the bisect, I'll have a look ... I have the advantage of
being able to bug Nick via Slack if I get stuck :P

Kind regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87czsmuuny.fsf%40dja-thinkpad.axtens.net.
