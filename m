Return-Path: <kasan-dev+bncBC4ZB2GTVUKBBTPTU3GQMGQEFPJEUPQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id OHbwONC5qWlEDAEAu9opvQ
	(envelope-from <kasan-dev+bncBC4ZB2GTVUKBBTPTU3GQMGQEFPJEUPQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:13:52 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C38D215F41
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:13:52 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-5032e68560dsf630502401cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 09:13:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772730831; cv=pass;
        d=google.com; s=arc-20240605;
        b=lxi08LfLZW7b2XfziKVgoaL9WX6mWJULmi6XoesQ0GcQ/BhxO6EVT6kVVsqOBqAC1z
         5TngGgJTCMgwcJ85p4ZMr94BPXPd+42EnVYSbIEJuc0Sv9RZXvYRosjuaztALdZc2kYv
         6eMnzsNYcQZr9PBmgMdqAqQFWqfHcc3Cmu6XeWB+4lLhbXks132k3ROkMtsmMRqj0Frd
         7g6329rCgiFBGng3jYhowhKr2+HNBXgPcxK7Jg/B48LLXNfHiK6WSY+JaQrzw2aBgXhA
         0J/y3QGQAqv9mbe3RO4nF0ga9Sqe1Rb+NqiukRvraxE09A15jMnrlcn+0e3UBE81oeuo
         H5sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yqTVa+OC5L77QSeRtZbfxMeKq4Ivo+E55n94QDtttk4=;
        fh=cHoLtTGFBJIl7Rys8vD+7LPTVRuu5wvO1yCnkel2cyc=;
        b=P9oRtY/gEph1rVR8XTBzebjLu5uRxXFfeuWxstHawcVEWuF34b9Yq+2OSCWCh7hqsM
         wGq2flP3WJ6Ueff68VrAtq7968sPwRqpyfGhCPI5x/a85nkEFE4ecmmqA5Uvn/p/AeN/
         nCvywyJK5F6pP1XVDyvfIH2IUo5dLOSFug+tkr98zYMzf+KEKNL9EPwQ+LwGnYGh+5D2
         YQTUhHAbgBPFQxt6x2ZnN0yvpuoxm5PNK2WRR/RRLrVUu3Gwaq9rn3EeXqraSNwjnk1p
         GDo6Der2Ij+FOK1dSKaX90eK+uMVD4nbhwW25Z3DCTeOqvf4hXjxTafWf9t7C+j1cdZZ
         EPEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fRWtGCwb;
       spf=pass (google.com: domain of song@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772730831; x=1773335631; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yqTVa+OC5L77QSeRtZbfxMeKq4Ivo+E55n94QDtttk4=;
        b=BvDOTIa8SJQTuCMXV4Hun/JItCHwJarfw8bm/Fq20GrKRO7X1Kd+Jrzdj44ccbBuz0
         LlhJBq8L4SovJehoaHyUyBjdDidG2MIGCfg2EzlkmLuDha9216Rny3CBMI1Sena+CyGS
         ZBo6WPrPTQhkEIKYASfxdvPeJq5tmg6Fs64qUUWl9HzVt47TrvBXqPiHoNKFEdOub6ts
         wU5pgoUep+KoPbG9D13ZUYCtiVWGsXzPP5efg2sNl8uMSRdDEkKYoQFzAarFr/Mr2QVx
         /unrljXMLOeJHNQVqg67cxy9yBQedrFEatHMTNN/177zGgNazm192LbxGHfLx+h/nwSM
         pV3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772730831; x=1773335631;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yqTVa+OC5L77QSeRtZbfxMeKq4Ivo+E55n94QDtttk4=;
        b=quqyTV9FTuHM+XISlmapiWr4GuJS9GvzPjuL3UxFl6EutYWEk+0Oc5xncXkE81bxq3
         vi82qam2Qt7E7Nnu5BtAVaAUJTo8IdlaeZ57sH2LNT4syymHZnf0oQaXS3VUOmsfahuN
         9IWgBzds7A+EfLe+qOAztNKZF9Q/Xn5BnpWASZuE7Fm0a+BeYOEwjkDFWb30rzD2qtEr
         m1uLjnzSRUdabxrbN+K60euQI24e3weHS+bFZqr5P4O2G4hF4bvgQ/kMjUODrBmuu8RA
         WJAyrTBz1JJdvCmEbsSWaoM9Yp/x038YDb40IWVMaNutaM1y+kNHzyJ2xhcs/BFYFnPl
         U3Mw==
X-Forwarded-Encrypted: i=2; AJvYcCX3OsuDcG0clUzdH08F7XlGjudDhYUMpHHnv6ae//0YMAl0xXXl0n1RwnuThaOmZzvlRzGM0Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw9pUF5e8LzQ7AdPPM7E0Ov57tiGSSGAGaIgOBRk/mLM2sb4LIN
	Cqz/+iqoKKIUV5lUj7GFYymh4WiUpvA5PwV4ggQJELYEKPjKvtZbv5SJ
X-Received: by 2002:a05:622a:60d:b0:506:a289:fd3c with SMTP id d75a77b69052e-508db2c91c0mr70076001cf.17.1772730830149;
        Thu, 05 Mar 2026 09:13:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GoZESgKjtrFREdP5EVzH/Kpy4zv0mR7fyls51UR2n4TQ=="
Received: by 2002:ad4:5b86:0:b0:896:fc72:fa4 with SMTP id 6a1803df08f44-89a22413a23ls23851646d6.1.-pod-prod-05-us;
 Thu, 05 Mar 2026 09:13:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXnnPtD1i9CWda7M8aD/iYWnuDTsYCRK/+6VWxRme1iBBYa+Gu/OAkcPsdaxnbVaY4Tf+/i/uO+ROg=@googlegroups.com
X-Received: by 2002:a05:6214:1bce:b0:899:fc7b:3885 with SMTP id 6a1803df08f44-89a19ce7e49mr99042366d6.32.1772730829206;
        Thu, 05 Mar 2026 09:13:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772730829; cv=none;
        d=google.com; s=arc-20240605;
        b=LymxZWF5cppYqB4o2MVMkxHRSt0fKiYPn75AVQP2OcxRpjE8ASLY0CmHaj+n5Atwrw
         EOTL8y7P2lKT0o72yo6aNpkECJ4T6FiIRLXE8dFGgsIZ/r4TJ/A9oUH3/Ir7++o0ykbe
         EiJBwgzRvyxVDBVn+iyLJk7bSv7mP0sku1zu3hMJ+B55An6CJdl4C4wxMC5XbnJpSbjT
         ql6vgTD2k5uaHoo20R3TYyncZsZdVR+C7S3/WNFQYXdy4gf5d3ac+Ml2YpzwBw6DmKFb
         CxYz2ZNXoi4S51XkkSw4QwJP9Bs22ygBtfmw6YILz1oRjJY1+u6PMZX+yASoUfTgtT8V
         B0Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Rrpft52mufttn7GrhsMqpGmK+xJpzS9V5p0MSwKGsxw=;
        fh=QMcn+jm3cSJecF1DtvwabBKOoGPyq4pgjfEPTFjeeoY=;
        b=iwn0/K2SnxwbZLeUZZ7qd+fIVPFW1e8SD5WiDoiehKeQbqEFB2DoEPbut7xc4VfDdw
         S9zlAAlWlDuIKxTgWvccGA8dZyeLvS2oZpTZ5TDR6I1aDReH257dwBvWE92X4zo+sOCe
         FXqhA20yCJOXdvzhUdKK/jiAnYFPJRqH22ZILsQauS4DpavoZzKiNBQt1DmAvlzJCMQi
         IcmXiDZPkJr+dgaqIe8J+6lSyTXwaNQevwntB1++lR2i97KFjvbpiM1S2Mm91zZkDqrw
         tpVDtl879H1xLdu2up+BDrj9DReOUQV91zfhO54+WNevVWJ0citgj8mqDyyLN34+6qjT
         fkXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fRWtGCwb;
       spf=pass (google.com: domain of song@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-89a0a564428si3004816d6.2.2026.03.05.09.13.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 09:13:49 -0800 (PST)
Received-SPF: pass (google.com: domain of song@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2ED02429EE
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:13:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1005EC116C6
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:13:48 +0000 (UTC)
Received: by mail-qv1-f53.google.com with SMTP id 6a1803df08f44-899fb2b94c1so65799916d6.3
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 09:13:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU/+uBjP2pCqunnyQLyC8t0gbbYARubMh+qpw6JGwn7B+BGnJl74KLc8oNRGUqTjjGKcBKMYk1XBKo=@googlegroups.com
X-Received: by 2002:ad4:5c68:0:b0:899:f51e:1ac4 with SMTP id
 6a1803df08f44-89a19d23a5bmr94544746d6.57.1772730827252; Thu, 05 Mar 2026
 09:13:47 -0800 (PST)
MIME-Version: 1.0
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org> <20260305-wqstall_start-at-v2-1-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-1-b60863ee0899@debian.org>
From: "'Song Liu' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2026 09:13:36 -0800
X-Gmail-Original-Message-ID: <CAPhsuW6FVGkpPymFq-oyqOaVNi5RDQhzq4Q0obpRehg8xWykXg@mail.gmail.com>
X-Gm-Features: AaiRm536rzWzAxRdjP-EaekkpO9ikXW8zBtQJcOWIpolslkK6lbwEnvjIdtlhms
Message-ID: <CAPhsuW6FVGkpPymFq-oyqOaVNi5RDQhzq4Q0obpRehg8xWykXg@mail.gmail.com>
Subject: Re: [PATCH v2 1/5] workqueue: Use POOL_BH instead of WQ_BH when
 checking pool flags
To: Breno Leitao <leitao@debian.org>
Cc: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	Omar Sandoval <osandov@osandov.com>, Danielle Costantino <dcostantino@meta.com>, kasan-dev@googlegroups.com, 
	Petr Mladek <pmladek@suse.com>, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: song@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fRWtGCwb;       spf=pass
 (google.com: domain of song@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=song@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Song Liu <song@kernel.org>
Reply-To: Song Liu <song@kernel.org>
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
X-Rspamd-Queue-Id: 6C38D215F41
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[kernel.org,gmail.com,linux-foundation.org,vger.kernel.org,osandov.com,meta.com,googlegroups.com,suse.com];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_FROM(0.00)[bncBC4ZB2GTVUKBBTPTU3GQMGQEFPJEUPQ];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[song@kernel.org];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:dkim,googlegroups.com:email,mail-qt1-x837.google.com:rdns,mail-qt1-x837.google.com:helo]
X-Rspamd-Action: no action

On Thu, Mar 5, 2026 at 8:16=E2=80=AFAM Breno Leitao <leitao@debian.org> wro=
te:
>
> pr_cont_worker_id() checks pool->flags against WQ_BH, which is a
> workqueue-level flag (defined in workqueue.h). Pool flags use a
> separate namespace with POOL_* constants (defined in workqueue.c).
> The correct constant is POOL_BH. Both WQ_BH and POOL_BH are defined
> as (1 << 0) so this has no behavioral impact, but it is semantically
> wrong and inconsistent with every other pool-level BH check in the
> file.
>
> Fixes: 4cb1ef64609f ("workqueue: Implement BH workqueues to eventually re=
place tasklets")
> Signed-off-by: Breno Leitao <leitao@debian.org>

Acked-by: Song Liu <song@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APhsuW6FVGkpPymFq-oyqOaVNi5RDQhzq4Q0obpRehg8xWykXg%40mail.gmail.com.
