Return-Path: <kasan-dev+bncBDS2TFHZQINBB4E5R3GAMGQEAK6V5MA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MLYmJfOOg2lCpQMAu9opvQ
	(envelope-from <kasan-dev+bncBDS2TFHZQINBB4E5R3GAMGQEAK6V5MA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 19:24:51 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 23D26EB9A0
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 19:24:51 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-34e5a9f0d6asf118399a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 10:24:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770229489; cv=pass;
        d=google.com; s=arc-20240605;
        b=RGQIZPrwYhsJ8q9d/nuM8dGCgCFd4c6SVLi+MYcncswuw/5eHPRM5VxtcohUAOUaHN
         dMZ7lbe3SHk75aAmV7KN/i4YtCK018w1RGu76tFLLaUi8h86/48rKTdhiykGYzjlQMRy
         DuG9fCl7KIlLOIYJ4s19b3h0cu+ClKD7q21t6VNmDUqvSgkVsiTwxKeUwK448JbS378g
         p7FjzEDfd/VSUWvDlFCDoYPBGHexABN8pAabRzNn+mIkU7ilu+3mhgpqF8n+OuKehWyz
         RAwSOBAu0McPsWKh8AsXiDvosw0VNIT8oyTaJbMaEqRUu5QWMQCHdqiL9CZFLJM/3oFa
         kTiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=bSl5/qDFvx/JGXXjyKRqWsPTJzbVqi1pCxL7CKWSfiE=;
        fh=KT9ozAgl4JaqHjcLoWtk8P9SNaW9n2n5T8zUJUOAa54=;
        b=aWlq74xEiUYLhLYzWBszd+mzQdLksN7AktDV+uQdqfppzlG8nmV5qUDObrp3QYlBic
         ApRPHUTRACdtpp/IjxqHyBSI7dkwzXfx7gF2m4iORUQPxFuCCEg/O9Fj0yYIpDVvYzol
         Tf33gjycuUSpuITqW5OeIDjUXWyQDr09KBU8sIZZKhHoa66WI7bi4Ftts/268n7NNMOa
         7nkOjQVUBwq9UKsy1gimjGS3diUqPdHY0zPZHRqjv+lzdMr3F9HjDaSSmBlAvE/+39ho
         ZQ1HP2iL14kuWVz5x2viMFZaJdn5DoiCpLBJvjN2sNeLTzaHocKfU8I8g8UH6wI06yGd
         lwtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b=I0BY7Y2K;
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770229489; x=1770834289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bSl5/qDFvx/JGXXjyKRqWsPTJzbVqi1pCxL7CKWSfiE=;
        b=spywqDktjxVTqLJSopKuWNjjH0NnDlHr+C2BWjfon/jn+nogBXks/DpulJarVb0z2A
         7Ha9Z2OCZZFkHisOpx7V3G0rua7gd4TBPb5eFil1WqAvk1dz70GLa7d9+QuU+9D3kNWQ
         BydjUfy2vy4M/KBUlg6X+hM4VJgFZEbsG12mRMFgajMhlzva+cGNadNH6Plg3uKOLB5s
         x68yGtw3NjkQSfr4rOiQeXVUXQsJKMiYFJVthxu0PcuSTcZXKZW8kCJRkVL2/v08gvEM
         CwB2tHC5BROtfxY648B/6glKDmHLi+WSX134KJUgSjJVdVXtWS4TdPrGIg2jFAT+uwAN
         w8Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770229489; x=1770834289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bSl5/qDFvx/JGXXjyKRqWsPTJzbVqi1pCxL7CKWSfiE=;
        b=cwcg219pYyOO9XsHgW6Ks500jX2mr71ggj8PAprN2I1AaSOlLl7ND8q64kC+qX5d4S
         DdHmmYpoV9rx2H/tIQeLL9ht04JqkelXlAYSbSF7g5Znyfpf1Iu0VrfnuDK+TtFxkjZP
         FVChpLuRUElBNQs6+gssr1KWxpbxuhc+kttLsCiga/3IXQQ8zXySw8nObcsCGctViEbm
         /K9vVEAw5Htp0U+20IyF+Q878OvQbBNcei/zXQOGXSnuPnp1oLbmq0ewYOQ2EgL5Si6d
         BFgn+a9NqDXlMz9LF7ds9NmREttRrAz5CgS3ESVenVZXDZL/yVFEg/8zDAuIkC2uE8gK
         YMzg==
X-Forwarded-Encrypted: i=2; AJvYcCXZNwdQ7Orw2wzncOiwDTk4hhH+WrwpK94hTs1yCNu9zllJUTpSANAos8KCCW6JWb3C1ZchxA==@lfdr.de
X-Gm-Message-State: AOJu0Yybe/UhBJBey7jpU+ad+OyBWmn/N25UzcutM3FoD0EenV5h7izH
	ZWlfDjTmFXl3vihvBoghkNMIqqKqMPTzER4s9spjkjGUrBGaO/R9ljLQ
X-Received: by 2002:a17:90b:2701:b0:343:3898:e7c9 with SMTP id 98e67ed59e1d1-3549bade66fmr251276a91.2.1770229488855;
        Wed, 04 Feb 2026 10:24:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FNZepb3ahvJdJ80s0encCyLWhsBLvXQKu6qSuEZ3AOTQ=="
Received: by 2002:a17:90b:538f:b0:34a:4aa1:8b1f with SMTP id
 98e67ed59e1d1-3549bbcefbals22577a91.1.-pod-prod-00-us; Wed, 04 Feb 2026
 10:24:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXCbihdj3hsQJDQ6BCZxvNi1GCeTAaWxUmwlI4cjbFYfPuCdK7+0jDDpQjBB9sXUo7COEFvS6n+af0=@googlegroups.com
X-Received: by 2002:a17:90b:3145:b0:32e:23c9:6f41 with SMTP id 98e67ed59e1d1-3549be5a5f5mr128516a91.5.1770229487352;
        Wed, 04 Feb 2026 10:24:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770229487; cv=none;
        d=google.com; s=arc-20240605;
        b=IMH5cRVaTWHt6gWzcg3VTR6GKkcnv8O8IBnYCElAL2WQ3yWP5+GDSzgKN59KOGxVLu
         1LwIIPIpiIhU5b3U11Mius0GwsYGHLrtN3k6Kt5ccnG3+GY63T2hOx3wbAUaugNC8iop
         T94gNJqQIUohGpU0uPtiiLr52zshwmaoWrUhMzujRLC2lcgFBx3kFNB7N4xev2E6pcHR
         pbvx4n0UdyKPy1mwRc5jZR8X0Sn+d1Kd14QT60YTeXcgZN8b6H2tmHzxqtwGcy26iEeq
         wwdgFjSiXNQEuNoBORPMRDAL17W1m74DYjMzx6MN05slu8p0hUgbWXi5FTV4+0fKQG9E
         vqUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=OdUb25hwDf7Td6RZQE9eems/6ez37ij9pWo0A8i9afc=;
        fh=RX/j/txVjNlM3s3xZ74qTB9h/GgnDmx7NC5+LBRA54w=;
        b=XD4wvMZ6uW/2xWcX44FX5MnFQvrvkkBEnTkwV7CLndv5R+TuJu4mOaGk9lJ/+G4zQd
         9s/QKryhc7kG7+bwrOsio7RSROt2xz5kiOpit+rC2LLxIKRLW0bA6r+y1cboScZZnYPw
         M6A1GbufLAiQPBaujSDuaoTvUn5VKTSS44CpkQuG5Njwodch0RT0bKPjn17lz2HBUmo8
         t/r1PVFu5i0hihwdmBip1I/CkAx7sFgTa/x+QVSkGbzYchkxOP+XMdxwcSe4CEu+W/hI
         6ZBKrfW3tSD9sQZ0RZ1fRCrQHPz+yhRkEfS4VK7zvD/KHqrshtiiJnm8khgC1faOmvSF
         tNIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b=I0BY7Y2K;
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
Received: from gentwo.org (gentwo.org. [62.72.0.81])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-8241d4506d9si96088b3a.6.2026.02.04.10.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 10:24:47 -0800 (PST)
Received-SPF: pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) client-ip=62.72.0.81;
Received: by gentwo.org (Postfix, from userid 1003)
	id 98963401E2; Wed, 04 Feb 2026 10:24:46 -0800 (PST)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id 95C19400CA;
	Wed, 04 Feb 2026 10:24:46 -0800 (PST)
Date: Wed, 4 Feb 2026 10:24:46 -0800 (PST)
From: "'Christoph Lameter (Ampere)' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
cc: Hao Li <hao.li@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
    Petr Tesarik <ptesarik@suse.com>, David Rientjes <rientjes@google.com>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Uladzislau Rezki <urezki@gmail.com>, 
    "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
    Suren Baghdasaryan <surenb@google.com>, 
    Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
    Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
    linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
    bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
    kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org, 
    "Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH v4 00/22] slab: replace cpu (partial) slabs with
 sheaves
In-Reply-To: <665ff739-73d8-4996-95e0-f09c3e5b6552@suse.cz>
Message-ID: <2abde505-1e35-8d74-2806-7a3cd430e306@gentwo.org>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz> <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb> <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz> <pdmjsvpkl5nsntiwfwguplajq27ak3xpboq3ab77zrbu763pq7@la3hyiqigpir>
 <665ff739-73d8-4996-95e0-f09c3e5b6552@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@gentwo.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gentwo.org header.s=default header.b=I0BY7Y2K;       spf=pass
 (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted
 sender) smtp.mailfrom=cl@gentwo.org;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=gentwo.org
X-Original-From: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Reply-To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[linux.dev,oracle.com,suse.com,google.com,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDS2TFHZQINBB4E5R3GAMGQEAK6V5MA];
	RECEIVED_HELO_LOCALHOST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[20];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[cl@gentwo.org];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-pj1-x1039.google.com:helo,mail-pj1-x1039.google.com:rdns]
X-Rspamd-Queue-Id: 23D26EB9A0
X-Rspamd-Action: no action

On Wed, 4 Feb 2026, Vlastimil Babka wrote:

> > So I think the performance of the percpu partial list and the sheaves mechanism
> > is roughly the same, which is consistent with our expectations.
>
> Thanks!

There are other considerations that usually do not show up well in
benchmark tests.

The sheaves cannot do the spatial optimizations that cpu partial lists
provide. Fragmentation in slab caches (and therefore the nubmer of
partial slab pages) will increase since

1. The objects are not immediately returned to their slab pages but end up
in some queuing structure.

2. Available objects from a single slab page are not allocated in sequence
to empty partial pages and remove the page from the partial lists.

Objects are put into some queue on free and are processed on a FIFO basis.
Objects allocated may come from lots of different slab pages potentially
increasing TLB pressure.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2abde505-1e35-8d74-2806-7a3cd430e306%40gentwo.org.
