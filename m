Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBP7EQH2QKGQEKA5WGUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 95ABB1B4AA6
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 18:35:13 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id a6sf2477355pfg.18
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 09:35:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587573312; cv=pass;
        d=google.com; s=arc-20160816;
        b=wqDBy+OxYt9LsZm5vVFjQui/BxvTWZ2eoXhVDIO8vkPEiqAba65gQ/uLsq/CUxPJrl
         9DVIUwLbBNQsOL9agS9iivH4qhrIB/Y2TYkQOBFHC3lmCZCAjxf8KevslUEFTPxuklGq
         wssenDwwbUTZW2u1XdxnBk+Y5pI6DvCJufVjDYWqUA11ujghsO1r9UhqB0U1G+/wnzCz
         98LC+CFo/i7XF/OJDh7kT2HLRi/JTHMghL4kCqHQFw/la94dBKWnLPGmTraLXWb+VU1P
         uK1F1GSUKbJpogPGJX1krecoLTCEog5xw1w+/2aMyQNrZcHFQyYvNIdaukQe+twhRpPQ
         wUKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=uwjB0sO4qNbXhu203MMOdtwXrTzPzqWQNQgCCYX/y+c=;
        b=xwtvFdjOLesT61DeJfWnzn1EHFHMGN6cc9ByZqikp0YMOa6iWu6rJngOrj1SxEstIP
         U+qEGNOIKBaSASgPSEoyo/dJ11bYOeGUNYjt1ach0dn7AG9YzjmDOqqC6loZwv18F+Tm
         HteqZTGfd8Jy23md3HsCL1q1kX8TQZz15SW9pJHS8KSatyggIyo7pcM5DDrSTYH2ejRx
         A+tI+QU3JguV0SS7aUPt/xrg5OtpOzXtmAcl0OzvPohe8IPW8QrfMh+6THLzUt4Kqs0p
         GKvpgxaG9e9mHgy1aYBN0ooo7Zwjcrx9K7svsXBALe/DoDX+VZ+bYUl1XCTwq8Pk5Iye
         2hKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=JbAJCGJM;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uwjB0sO4qNbXhu203MMOdtwXrTzPzqWQNQgCCYX/y+c=;
        b=B1whwI6DoeaUVRIqWIcuGnWnm4hm/KvkJhkYqppHshzut3ySEAFVB4sNdOp9lmmTHv
         lGk9FK5mDvhf2GsRgfnhM86lYyU9yg7mg4loqixs2XgK2IYl/2eQo9K9t9QcnlIGdQp8
         GXuonFh190pT+HBEJmX98UN+gS62aq7P97Ai/X/yt6JCH2TaZ1XS0P5cuRgqk42SqT7i
         JyF4mn1XavEe3szwuHm5NyV0SiMwoqHxcxNBtaN3ZFM35dIZN2KUogv+3Fqin2NAMeBD
         JtJ6VGyaU6DmBBx2p1skn3VUGbvmq8Sg2phhN3OBuPUJQy4Ccxl+Wug0riboh82sZ4Et
         xbCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uwjB0sO4qNbXhu203MMOdtwXrTzPzqWQNQgCCYX/y+c=;
        b=JlF4nHiuDzrS2HU8dJcoK2Ozd5nwZzPcajysL6Qwlz4OL/mcoLBYDpuQXr9FRW3Ynn
         dqbE0EOsTxvZNLDg/B0wsVXIbLhsXShAUorwDFIdOJSeXjQfVwHHiXqsAzsvVhstFxp2
         Rz7pCyUTDXDX5c+uTaeLFbUIAu4WyVCHH6hdBuZuAsXxCYMX/7KFzHe4bgrdX/uWMLj6
         1EcxEsNc6y8xVRJuzoXz+t3CNF9eiv7OAZLydHRjjOjNfgs/UNsIVtOuir39kEA8iwAO
         aheuBk7HR10kOq/8YXF8ciLk5G2IfMwbqXx2QQdHmz4rrxCHXm1GFWVw0XEfB7Jck+wr
         EXLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaDzmxh2owpD6QnORcA+oYmiWLIuuoEDcUGsQVGW2ODmsAytdDJ
	Vujcw0v029QkZq0mDNvNJUk=
X-Google-Smtp-Source: APiQypJEK9uiNBoz0tuIfMNXjJC5RVb03FdsBGZEOuZJs1OtNs3n+xg+zlK3BMb7ZapPcpGnR7qb1w==
X-Received: by 2002:a17:902:bd87:: with SMTP id q7mr1689047pls.92.1587573311891;
        Wed, 22 Apr 2020 09:35:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:68c1:: with SMTP id d184ls1462503pgc.9.gmail; Wed, 22
 Apr 2020 09:35:11 -0700 (PDT)
X-Received: by 2002:a63:2a08:: with SMTP id q8mr12725793pgq.442.1587573311402;
        Wed, 22 Apr 2020 09:35:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587573311; cv=none;
        d=google.com; s=arc-20160816;
        b=RyedaY6AS7L8PHtI9U1/gKlhW5oSWvAxb2yn9Lk1DYj0kxnF/uu1RTkt3NVtqzLj5E
         eOEzhN1sagYmSYtUfcBEa95wQx8rr4quyJRUr39cCUCl3gOYkztdczvBcIfRKxLIvIKZ
         QFCPH+a1lFQrz1/GlOr4OwzYouSbEBX4uExcR7eF1ZHgBU7iT8tzp11Xv+Dx2KG93v/6
         nfJ91LwwYyxtyPyhMevQ7yc6WjPshABU4qkLHtKPmm2TmvnwHZdG2KQnHTTqGBh8Ys7c
         e9kLER7OSXHKKbIv3Ia8dpZE83GwAQtmLBuS2qqDF995E1EYlfrZUFI2puMWJ8KAhoVw
         wMRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=DqTx+R+JV6vymEcgZ+pw6C27qjNlWqJpkbsx1i9Y7eY=;
        b=tJHT2IyvfPR6uvz6uDSXGW7ziTEZhF9pdBOqUM1l1ZVuZo4cdIMN08FkZtqTffGTjs
         dpMv5tW3im1o1EQZ/c5tszGoQsIEYYjrP2mCRpULQjiAs9G1VbjbmlSpHUG3+f3/Avmx
         Dh+XMPbQWpaSB+/LtulYnREOwolGPa9XTd3rTZGHDNv0fYqwzdjaGueSyCMm3EKRwNcg
         lVWZYGF2sYi21DboYcg6bsGVxotS1HGjN5pCoJ1RRBwzoM0ziUXMsoCeDbactU6ANk8a
         APYcG2nIQfwppaaIZ3HTmLxw/Yng7FgC3YXrOy0oP4v+xjd2Vv8ARQF8+sFmu/SJvobP
         o6UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=JbAJCGJM;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id 194si477363pgd.0.2020.04.22.09.35.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Apr 2020 09:35:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id t3so3078937qkg.1
        for <kasan-dev@googlegroups.com>; Wed, 22 Apr 2020 09:35:11 -0700 (PDT)
X-Received: by 2002:a37:a090:: with SMTP id j138mr28112903qke.168.1587573310995;
        Wed, 22 Apr 2020 09:35:10 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id d17sm4408130qtb.74.2020.04.22.09.35.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Apr 2020 09:35:10 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and pgprot_large_2_4k()"
Date: Wed, 22 Apr 2020 12:35:08 -0400
Message-Id: <59604C7F-696A-45A3-BF4F-C8913E09DD4C@lca.pw>
References: <20200422161757.GC26846@zn.tnic>
Cc: Christoph Hellwig <hch@lst.de>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>, x86 <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <20200422161757.GC26846@zn.tnic>
To: Borislav Petkov <bp@alien8.de>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=JbAJCGJM;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72a as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 22, 2020, at 12:18 PM, Borislav Petkov <bp@alien8.de> wrote:
> 
> What is the special thing about this config? You have KASAN enabled and?
> Anything else?
> 
> I need to know what are the relevant switches you've enabled so that I
> can enable them on my box too and try to reproduce.

The config has a few extra memory debugging options enabled like KASAN, debug_pagealloc, debug_vm etc. The affected machines are NUMA AMD servers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/59604C7F-696A-45A3-BF4F-C8913E09DD4C%40lca.pw.
