Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGG5XWMAMGQEQ4OEZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0011C5A8003
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 16:22:17 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id n28-20020a63a51c000000b0042b7f685f05sf6865999pgf.13
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 07:22:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661955736; cv=pass;
        d=google.com; s=arc-20160816;
        b=lezohyOImEPBTwL4I7ETgpLg50g2poTQDMtxaBaGs7p0wcvZPGjZJQ8EKZDKzAon3X
         2EWxYmo0qwYwlMzKLLuNA0dtfCiK4ZuQSC2PtTs0u7dv+WGIUZYAZ6twWtD2PLj4gf5Z
         Lkgfq+/WSAthcDLZ/SeyqODGx13OcGlayJK+b+YkJiHWlO9g41hOfkpnFj5Vetofct35
         T0crPdvDUmWuHO+SZ82Y5CcHnrRuaBcYqilgjU+dpUxhYrTLYCOpEHr6lftrISpqw11Q
         9BqZU7yRGJLOM0fv1IJ44Er7B+j/dGqKvq0NAq7Rf5F8LbV/LMhkmFyuALf1BIkhKFW0
         asjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0qtfq0vdoKbVVmh5nuvjy3/P+IbYmGVeab7bv6gOdRM=;
        b=x7NvsTJ8yBvr1DFnN6h6EALtd5lPqg2jaRYTLchGO7wis7C/zzhEkDedWPsmWIdlsE
         8Wh2oWpkoobdg8wnK19p0gDb3CWLNUTAMzmIEF8PoFNHaIuLqnenpwVNRTkeHllz1sTx
         iiPfCFshp/1ZNgFLBBuIWnRRrbWrYJ6Jn4+YYUaFFMJVP/edIno0+uJ6jFM2S0XPkISf
         lkngCgkao69f6JZuXJUY79wTsJTZVMgpfHeKGu+B2QoCe1LW2CukeLU/QixNgKi67+IL
         Dj4akuurG28MCL+0WfemE1GOXWXzsVE7KysAkr0ftrtKVCp0nrwNWdMvQcfeOnKhtDX2
         4Mdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HOzZcidb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=0qtfq0vdoKbVVmh5nuvjy3/P+IbYmGVeab7bv6gOdRM=;
        b=gAmY0bwyhr2XzPTxmmttD/NxNNOkCjoc/bII1W+Dl3ifqJP1Q/YIOn9V4LrBeGv4ak
         sdsPzYHq5BolPK7wmvtWMYq0rvtmtjZgWKRDW8MOL2PpTw+XtZPDcyFFKJHtxxlLB0KE
         1oYMuOLv23/tPfE8DUCY5vSnNOBo68O673z8ONVLdNZfoGN8NR8y45r66zpo5fjTA63t
         LaL04nvCKM7UEpc4mOpPBIl9rBbRH6Ngrc6NFuiRlRlIf6EiKOP+8usLX1Z+7pT/VbVv
         f40CpCHyItLgtY7y5QOxOuoKb44x5DGJyIqqSiCJEkWUzNA/CQScdVEevpH7c3WDd0wT
         7PEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=0qtfq0vdoKbVVmh5nuvjy3/P+IbYmGVeab7bv6gOdRM=;
        b=1Cdcdnh/Ua9fN3QIDSfKllt73duCvh8BcjEVVB3cwb5wx5r3bH4VzOKgT0VF5x5yNq
         Ose8ZEiQuoGAKWBh9ws1R1NoaUw92Jqe4bBnqn7DeKx6qQm8EbNixxXeK0c8QFII5hZE
         +UtXXXBNMymrYh7O1IGLbhHlj8psbcDjmMGYuoqnUFx5v0IZ4QNw5qpgu2TuyZus9fcp
         j0M9jNfFxGBUV09g9oNLnhu6rrs4XxtZghXGEyYVtA7usZSmqMY0vPA598ZEu8hKlANV
         H7ad9YVemykYd2OoUMwS7PhR7hwT+Bpxc95biKKYQxvve+pFCM3k8nuwakzZML8bN39G
         MlQQ==
X-Gm-Message-State: ACgBeo0gmFriyYubcbJKUNli0bA8ZE5QpgV+6znzXIpHO+zkh336ZLXc
	otvTcVDvqi7wJAoRFHSLv0w=
X-Google-Smtp-Source: AA6agR5G7bqZSJaXNncLj9Z0O+GNoy4D3pAE3Or/16YUgCpUswJTIGd1aTvDcwjRajq6+lgU8ajXyw==
X-Received: by 2002:a17:902:d4c2:b0:172:c519:9004 with SMTP id o2-20020a170902d4c200b00172c5199004mr25607794plg.154.1661955736363;
        Wed, 31 Aug 2022 07:22:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6bc4:0:b0:42d:706c:5bf7 with SMTP id g187-20020a636bc4000000b0042d706c5bf7ls2797424pgc.8.-pod-prod-gmail;
 Wed, 31 Aug 2022 07:22:15 -0700 (PDT)
X-Received: by 2002:a63:f50c:0:b0:430:41b3:4470 with SMTP id w12-20020a63f50c000000b0043041b34470mr1572421pgh.83.1661955735534;
        Wed, 31 Aug 2022 07:22:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661955735; cv=none;
        d=google.com; s=arc-20160816;
        b=AjTpq7KsnoJXFL32Tp8QFTPDwqm89PB0SFeDz6wwcBZWG3wIw4zALiih5wCng2dQI6
         VLGo4o4xsZ2xCBIDhnVv0S6PmWulKfrP3b0+ABn7DuhVwHQuqeRCyXrA+j7rWIUWmqRV
         KFR0SB+StGLTICsGMVvGfrjfL+vPKEy056V8x3QioShOco1VZHdKyjvfA7RHKecrJSdO
         tgts0O6vjU+F3F7R7edIczAMNGSaiwKmmbVqMZs93Ck5Rzt/4dJGLmhsCpPHmOzaG0UN
         aKR6t//3Rwy12PiJMjqjduu2BNEsk3J6QgnK3WpdAbTrqKkbDKI3JYxOKMVtZDPYD8RB
         t34Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4Vg1ERH9wjNtniBTUKn8Tr6pE15waOtgv9dBP63mem4=;
        b=GrRou872a9FL+ccdG7P+3sdIeINM4FHLQwPZpa5uxR0bP56JAhonPrItEQdJWuaMO5
         /NJDZEhKz7dRxwCmFi6gf7S3O6xjh5yC8W6vwv1pIS21wn+EqdiZyafLDzDYZ8wyIq/T
         q72v/1K6spBIKIWD+W88pTDIDL4cRVTCIGfyofe56FlJah5Ld0EnlBh6HN1oEKIXn18a
         DHy4Sx5kKpCgzsAVOGIbX02LDT6Z1KvU05eFVTBNLL47X2rmyqFdcqT/t+gwE67ItKB6
         IoXUn/zXxZVmY2HH6I5BnrC/0or4Gx5UNgM4xcftUid2M7Xqc9BQ2uuny6f3aBHKJnxB
         uerg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HOzZcidb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id c1-20020a170903234100b00175099477b9si235464plh.2.2022.08.31.07.22.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 07:22:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-33da3a391d8so308913557b3.2
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 07:22:15 -0700 (PDT)
X-Received: by 2002:a81:bb41:0:b0:328:fd1b:5713 with SMTP id
 a1-20020a81bb41000000b00328fd1b5713mr19205749ywl.238.1661955734705; Wed, 31
 Aug 2022 07:22:14 -0700 (PDT)
MIME-Version: 1.0
References: <20220831073051.3032-1-feng.tang@intel.com> <Yw9qeSyrdhnLOA8s@hyeyoo>
In-Reply-To: <Yw9qeSyrdhnLOA8s@hyeyoo>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 16:21:38 +0200
Message-ID: <CANpmjNMFOmtu3B5NCgrbrbkXk=FVfxSKGOEQvBhELSXRSv_1uQ@mail.gmail.com>
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip list
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Feng Tang <feng.tang@intel.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HOzZcidb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 31 Aug 2022 at 16:04, Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:

> Maybe you can include those functions too?
>
> - __kmem_cache_alloc_node
> - kmalloc_[node_]trace, kmalloc_large[_node]

This is only required if they are allocator "root" functions when
entering allocator code (or may be tail called by a allocator "root"
function). Because get_stack_skipnr() looks for one of the listed
function prefixes in the whole stack trace.

The reason __kmem_cache_free() is now required is because it is tail
called by kfree() which disappears from the stack trace if the
compiler does tail-call-optimization.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMFOmtu3B5NCgrbrbkXk%3DFVfxSKGOEQvBhELSXRSv_1uQ%40mail.gmail.com.
