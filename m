Return-Path: <kasan-dev+bncBDTMJ55N44FBBYXG3XFQMGQEKLN5MGA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id sGZ0FWVzd2n7ggEAu9opvQ
	(envelope-from <kasan-dev+bncBDTMJ55N44FBBYXG3XFQMGQEKLN5MGA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 15:00:05 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E438B893AB
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 15:00:04 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59df09e2560sf816221e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 06:00:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769436004; cv=pass;
        d=google.com; s=arc-20240605;
        b=iUePCT7BiN5UWgdtC2CEQEz4SD0JM6MQa1kVT/xNlEk+CaFfbMb41VS2q/kofg7ILR
         ws331Fk9UyPgJLYE1EcAsh8xQoY9vtH720fMS7vy9mN2CaBwqt9F3b5MPdpk19T7RHyw
         YfrvZm3KdeXluryxFnjLPy02w23kAF7KsqbfF8nSk1zIDE7pJzIR8RfOqVQfAHmjQvMs
         s0YtKPZfvvAN6ENpOe5Jq0oc3TEAlpIdp0/45OyPSh3cjeZlhJfL2gllgnOTJIrq/46Q
         /G9CLl4wTd+bJgAipPzX2wD5JkBP3HbU2EfVC8K23kKA5z1lBS3nGLS+iJR8ugzv3DjP
         0ziw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=r+Qaswa9K7eDgX7HzCuWrmYaPWViMm/lAsGTduzUAHI=;
        fh=DsEKaJCUpQWqYAhsves29W6KL3LBIRBXVZQZN8kqkJY=;
        b=JL2A11cfzNiQrNjaz2yukC19e7FMqwbpw98jpopCtJ7txeAnc+nZVGAjJom5Es29LB
         T6e5O2d9nDHTa1gAi7llNY+SIWeEPZfQjcaGqjtlKLf5RQnNntESHMnFWCv/hRiV6684
         2QjJ2IDTP6RGOWP9AfleWtRSoipWbnyivRVjbeMsEPY7N/HvSUPUTj8e9TCnRr9E3L81
         G3jBnvYyV5TYRMb5OTFOh/6WHEc31g1iU+azCPLJIVizv9FK2vEYFgd1t8+PN9qnwsws
         RohnYG7/mHGZY/QEtgXfJtWeGshZy8/ROMIPxfqHE7Sq+D7UMMHNmS2kLuvJM5CC9H1G
         nmMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=Q7sbxvHC;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769436004; x=1770040804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=r+Qaswa9K7eDgX7HzCuWrmYaPWViMm/lAsGTduzUAHI=;
        b=u08pWN3lb8jwy+5nQ4AlgN395MitwxBzJKXnq1249VAKmFSJUIb2DHVt6ADcNN1FfY
         094uR+um++X51PMFWLxCf4eHUvqOpCppSbS6rLrK2uy57iW6jMYH/zDC+14wZygWl1fm
         qowFJpvaOaEpaRULaNWmAaYvgBRWy/t+/Zqtl+0dahvjwyShHiaucERlULS8K+YWNvtz
         DtD2SLL4RQL+7GAweLuweuIU6huD/H1ejLNhWBIswFkxk4jLdQPnYw5J9TEBlyrS4eTR
         UbJ0z5xeBVNpZbe4j8KecfwVS+MTd4V+PmxtRtUCJVaWHF3qA6IBaFxnsXQCpAnIqBCO
         hdkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769436004; x=1770040804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=r+Qaswa9K7eDgX7HzCuWrmYaPWViMm/lAsGTduzUAHI=;
        b=n2fl+NBaR8GiBJkAL9bzQtdnVBwMHTDeyEqhBBI9rRc7uoeuRJZ2caugY35cfkiOKu
         /h/qV5v1meUwvrU7rMAOStfTtMOoN3EFDiHEiGKTRmVT5N+fEywodbJROQuhB7jlmMgw
         /omwaxnNJkkUC3vc9QDOgjIy08rPpa+ug/eI+CyWBzI1Q3LFNZftcozoivdB5s49iKvT
         0ysbWfwt+PFvbMmDPyuymQZT8wjzlwYw8PQfqzbjzTR9RuPJlIm+Rpt/mt75ozUgDbJ9
         lOaKSbLHrddZjRWdTZ1LctBhB0ZthwHAOyl/7tLUvj4uI4GwFGRFVmbioMYr3JAI+Gff
         YIrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHI98oQJayLiiTjw1rWeb4FBMkBGMcSBt0JisHMe1vMFfKnpijJ5GK//zq3B3ex4F3gSzf+g==@lfdr.de
X-Gm-Message-State: AOJu0YxKmgj/TcUDkAa9DyMiX55GlZnMUcft161jX7CXCXvdMlSdLi7G
	qt8q1Vydvy8jdmiMuN+7/86tDYPbEGimFcjkjN4JiAevJogWF5lGw8eA
X-Received: by 2002:a05:6512:10c6:b0:59d:e7b4:f9e5 with SMTP id 2adb3069b0e04-59df3a393d9mr1263416e87.38.1769436003511;
        Mon, 26 Jan 2026 06:00:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GOSAuAGNIzLn/PNqcxMXd+Ufaj9urLo0F5IxZbRuddEw=="
Received: by 2002:a05:6512:4005:b0:59b:6ead:861e with SMTP id
 2adb3069b0e04-59dd79718c0ls1516942e87.1.-pod-prod-05-eu; Mon, 26 Jan 2026
 06:00:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX0qPHni5JmxDNkVSiU0nVF7eoskmyCiB5uvl6vRu6nmzA1EclfnuV2FTzOdLxksfdU7mvx3gbDnQU=@googlegroups.com
X-Received: by 2002:a05:6512:ba7:b0:59d:f2f3:7e9a with SMTP id 2adb3069b0e04-59df3a34f73mr1455280e87.36.1769436000612;
        Mon, 26 Jan 2026 06:00:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769436000; cv=none;
        d=google.com; s=arc-20240605;
        b=bKNGtE8r5RK7fsXko4Hqy43ZANY9+scqco8G3av0l4PFRsfQTFM097So1UdYi94vcm
         OLwebGG/+RLkBPAx3cXnYaCL18NyRhLbE3qtVLnSggLDKGkbT2IncySlQ5T9WQtUdti7
         yndQUzR/utfY1SUMdDM5sJTED5UmuhhqiemkfDYcMY487Y00fg9e1qdk5rMaBui7ApTp
         /d3/SMc/EhLuCS/uBNdpplCEFeF+qFjnjVTBC1Bg6ZjgFVs0hoFiVmNdx6wDeIwVYmHo
         7b5v+YwWcsEmxkYUKT1c2QH8l1QPZEqryc/W8nw/Ws1cSFk4KSzQrZNfJNC3pFhjJHHe
         Lz9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CA7ZM6arGeM7G5r4XYd+i+HkxrAcrO5ouJ48DYGWkxk=;
        fh=KwC7Jum6N/o025Yv5BbBtrdUqOkm0+yynzCyRrsFo/Q=;
        b=Dli+ARzmqjdLNCtdtdfn/gv+lEEYQgNr6tMY9fW1erFpb9RCtTTUh230kCvqbL74Mi
         wZcx9pmlrpJHe/5hiKmxnAw/XOfheqV3Ct5YA9i/6aOWnyreR+dhWyDHDSOIxo2b1r7E
         qYzs+70z7C8mOkQv+smk+YAdOf27uFvzdaHYx6haHhUpAJLcAZvk3D4ddHpeC844y508
         /imlzQmOoB6qfq/DIIvQE97SVSJev+TnbJRoKeRLWUc237f1SAfyIwCyClpCweEs62DX
         UsENIJhIShE5RmyvjEbmuwvoEKFdhPHS69dfGc8RbuOMqTnSFayu4Qt+HdRIAcHnSWZP
         plQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=Q7sbxvHC;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de5ab3aa4si194928e87.4.2026.01.26.06.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 06:00:00 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vkN7t-00GDx9-Lb; Mon, 26 Jan 2026 13:59:33 +0000
Date: Mon, 26 Jan 2026 05:59:28 -0800
From: Breno Leitao <leitao@debian.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 06/22] slab: add sheaves to most caches
Message-ID: <aXdzLk010qbTNbUh@gmail.com>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=Q7sbxvHC;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	DMARC_NA(0.00)[debian.org];
	RCVD_COUNT_THREE(0.00)[4];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[leitao@debian.org,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_FROM(0.00)[bncBDTMJ55N44FBBYXG3XFQMGQEKLN5MGA];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,oracle.com:email,googlegroups.com:email,googlegroups.com:dkim];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+]
X-Rspamd-Queue-Id: E438B893AB
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:44AM +0100, Vlastimil Babka wrote:
> In the first step to replace cpu (partial) slabs with sheaves, enable
> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
> and calculate sheaf capacity with a formula that roughly follows the
> formula for number of objects in cpu partial slabs in set_cpu_partial().
> 
> This should achieve roughly similar contention on the barn spin lock as
> there's currently for node list_lock without sheaves, to make
> benchmarking results comparable. It can be further tuned later.
> 
> Don't enable sheaves for bootstrap caches as that wouldn't work. In
> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
> even for !CONFIG_SLAB_OBJ_EXT.
> 
> This limitation will be lifted for kmalloc caches after the necessary
> bootstrapping changes.
> 
> Also do not enable sheaves for SLAB_NOLEAKTRACE caches to avoid
> recursion with kmemleak tracking (thanks to Breno Leitao).
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Tested-by: Breno Leitao <leitao@debian.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXdzLk010qbTNbUh%40gmail.com.
