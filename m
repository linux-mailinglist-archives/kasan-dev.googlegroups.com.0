Return-Path: <kasan-dev+bncBC4ZB2GTVUKBB67UU3GQMGQENLA3YFY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mItTJH66qWlEDAEAu9opvQ
	(envelope-from <kasan-dev+bncBC4ZB2GTVUKBB67UU3GQMGQENLA3YFY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:16:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123a.google.com (mail-dl1-x123a.google.com [IPv6:2607:f8b0:4864:20::123a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FA6E21601F
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:16:46 +0100 (CET)
Received: by mail-dl1-x123a.google.com with SMTP id a92af1059eb24-127337c8e52sf46027980c88.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 09:16:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772731004; cv=pass;
        d=google.com; s=arc-20240605;
        b=IM9ThHmjSGWT+lkKRRIpbYtBktkN2CpIO4F553bxmwIwqEdMZ9Jkcs2nOAdXeoF49h
         Eb+xNA7Idln60cAT/sBEP38Dk03w0QG1tmhrTnOhfDB6GQxfqiLvcASko5nQ2QrkJdaF
         K2baVNUU8iK06uGdtz4VOntN9CbOIe2Hh6LcZmh3sGE50XNS7fKX4V53JScWQqpn2bIr
         SI71qiXqvpio3RAMFfQW1GeJPsipqd+escOvVYn9FTEEOZ8VLwfgIPP2CcA3eIvRx95q
         rL+xbIU5C7zk0V1HcBudDaBc0P0sGLqIOMVPebDkx7bv8sCd3kpPOZC62V9LtlAVDwks
         3BbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AVk26z+t9vGg1NygWGI1AwBSCMKeItawaUyRT266xkM=;
        fh=0GQ+2PhJA9RAuO1j6/ZdScFZ3hC+GqgDvWja0LJTqTk=;
        b=Cn+pMgqY88fn4NKvDbv6CurI+KUzDuT+Mcwlr5tA5kFXE74ciWqJ94BMGAqa4Gi1fH
         bU3QEusglrVfCaN/DNSEPyhg81rnd7tpifSBroii/gLA271nXCwi7qRVfpinPUhMuhor
         A8BZzmwvSTFgjg8Z5672R7xaklGLE9EZNr6KGTtCkHJMEgoT7ySM98CpOc7EVGFLXWts
         diW1yoY883ygbPpH97nIvD4chCuINwLj2yel+CwZrLv/3vcNb11uf5B9lJALQcnvuqng
         a4cMAN92ZYMnHg1c2mAIn8NOe2nPcap68tm/MynlLyPiIXziM34C1Vzp/tcBJzJ0PGnO
         vUWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SN736VYS;
       spf=pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772731004; x=1773335804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AVk26z+t9vGg1NygWGI1AwBSCMKeItawaUyRT266xkM=;
        b=qrhQbJ9f87bbxucof/XMPRUZc9Vr1Ba47VeCF5qWcoH2Q9+Jb3tbZ5bhqPT0qlVNYj
         CoK/q4eie98PtpByF/iJdcT/PzQJ9L4XTq+y8KGJ7VfY/SoY49C5/UWdPGyJRmwLCz7z
         DSxG3wt64HrZ4vgPM438gffeg8A//IohJLizk6h7A4EoFYtpUgHcMm5wn9awlZtX20z2
         fLy48pHsq3YSvwTf8xr43SbfHTW56ILZnTVwGRlMN9I0yd9etLDfQvN8DtsgYpu9kGxI
         NGzf4BLpHu/NFRsR16nfz6tUiKuRZjs5X8sRLa93YuJ/EOyyDa1UrmJrYvTsJ1Hgalbd
         ZTKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772731004; x=1773335804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AVk26z+t9vGg1NygWGI1AwBSCMKeItawaUyRT266xkM=;
        b=CgZa3UqCZuDtPJJypMka4JamaYLVW14VL0PHhP4Mg9OUOFlkj5T6psjNyLpQyqG1gK
         0NrdfRGce96ZaN0uqP72h+vTfRp0Y39zMDD3m3TP/jObMb09kE7lVjAAODqKn5wvyQFA
         QRFh5fXKGK88++nDdTtMYIxHR2ddzM/JiuFKwgYR7oX4OL+71Fr2nZiTxiO0wZP44A0g
         h6J8cquthLzvyQJ8ug/cSYkRx0n9tLcphClxMpefddZEiM8mNrdruuDOmvQ1XdPB0yNw
         r2PAPKTcjiZWy8XG9UhL0Cmbr+GsglnSXCWt7od0w+yNX7AzVXOBZRQ1BxXvy4I8MeXV
         9xJQ==
X-Forwarded-Encrypted: i=2; AJvYcCW0nqDGdYtiVdo3AGooK1sYMDO6vIB8F2tNRSayEIcqufY0i+CIIMfhaPURR9gX3DFutmIfXQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw4f8hLqgLuesg55cK9Hswm69PKiNsuU7CPxY8xaqNa5Zei/g4f
	M2Da4F9r8/CFUeiuP3+pe8urVEVfyl50u9CCnzKRQGOsnrbnEVomSbv6
X-Received: by 2002:a05:7022:ecb:b0:127:867f:2448 with SMTP id a92af1059eb24-128b70d1443mr2592591c88.26.1772731003841;
        Thu, 05 Mar 2026 09:16:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FTQv7nB0Gw1dMRA1glOWyVvrsAniqEIpHoecdmn7a7wg=="
Received: by 2002:a05:701b:4201:10b0:124:af3f:199c with SMTP id
 a92af1059eb24-128bb03d512ls697406c88.3.-pod-prod-02-us; Thu, 05 Mar 2026
 09:16:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWLU6LftOo9JRA/VQFzLyOxlqC20ixFc1sKGIdZ123UvOUqWR4Kwz5BcBMMW0QqrWQvZd877Ob5G4Y=@googlegroups.com
X-Received: by 2002:a05:7022:30b:b0:124:acc6:6dd1 with SMTP id a92af1059eb24-128b70f7458mr3481292c88.46.1772731002237;
        Thu, 05 Mar 2026 09:16:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772731002; cv=none;
        d=google.com; s=arc-20240605;
        b=A5kgLR2PhrGJWHvPhTIbcb7CjwpvxunD9Fj6T4/Uz4iJSwJvjGrMxt0kKoDVodfZFE
         gafI2eDQ3M6S0ZgLt2QrHecq+1tSKEqB5/5PAiut1hTLxg/oxHJDgVS9bAJwAOw9QFyD
         6k8EZbiZLB0BmaLoUot43qkYLtxRsx9r4TVty+Wxyj2GQxDO7h76RsxWPmdiZTCfayju
         KQgcRyY0fQ07WK5E9de8d43dee25cYE7aKNGtnMmU371SSVhXjWZwm2FGADjQ1Kj9jOc
         XfVlQW/mUyOGCtT1JxY291cKIKpavNUkcKaHFoQzK+C8psZUHGuBrV+MRJ8mDwnd0y3k
         g58A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Q+ySlOgZD/YYlOQ1FApBWUVFt4KGG2UghPTq2hdTuJg=;
        fh=DG4GcqLxlBw/IcPuRq6p+dWefjsDp9bVvFNC83+7FCs=;
        b=YUnMNlyWJfU5z/9gcw/sCpGVmhf1gkcjp0bk4cOK27Y+aiO6GoS/n5ZdMueFLA0Ohk
         0hJGHG8ztGjXY3j8U6rO5yChDr9BwODncYeIwEP0uPHV1LqHUSISD5DfsA63BiCYPtkD
         UDQmdzx8dwpD/292EJFV76wBQbvuf0UvP3jPHvWx8/P43XKURUcEXOahbR1FOf8VGwgN
         WRh8NbuGwlLMHOkaw9yU0+7OWIU6RS+ZlsiKJI/4iKsPuP3VMq3pndYWuYqRfeBSkMCU
         aC5THHqt6DhTM4fNfJqDUP/qkXfbwzizEJR437osd/WfTIZQCD/N6F2emxm21ha+f9Dj
         llHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SN736VYS;
       spf=pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-12789a22931si834107c88.5.2026.03.05.09.16.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 09:16:42 -0800 (PST)
Received-SPF: pass (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C4F296001D
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:16:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7764DC19425
	for <kasan-dev@googlegroups.com>; Thu,  5 Mar 2026 17:16:40 +0000 (UTC)
Received: by mail-qv1-f41.google.com with SMTP id 6a1803df08f44-899f27df3d1so49531136d6.3
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 09:16:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVsj1Wnn71mb7VfRJFZ/G5sEIHiTyXFPL0+LlZxqhXLLBxhvApi4PTHg9qiMMFJeCkFK6RNJ9CuIs0=@googlegroups.com
X-Received: by 2002:a05:6214:252f:b0:899:f0af:4f51 with SMTP id
 6a1803df08f44-89a199a88a5mr94803056d6.20.1772730999587; Thu, 05 Mar 2026
 09:16:39 -0800 (PST)
MIME-Version: 1.0
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org> <20260305-wqstall_start-at-v2-2-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-2-b60863ee0899@debian.org>
From: "'Song Liu' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2026 09:16:27 -0800
X-Gmail-Original-Message-ID: <CAPhsuW4Z1XGZV3A7gwt6X6K-4VjbS2uBG3FbF7u9BK+MKO-7sg@mail.gmail.com>
X-Gm-Features: AaiRm520DhluBEiNd9TcnS_RjZRGJvQ4KNmb6dUWtAIxon-wXq7wA8Jy4CW5OH0
Message-ID: <CAPhsuW4Z1XGZV3A7gwt6X6K-4VjbS2uBG3FbF7u9BK+MKO-7sg@mail.gmail.com>
Subject: Re: [PATCH v2 2/5] workqueue: Rename pool->watchdog_ts to pool->last_progress_ts
To: Breno Leitao <leitao@debian.org>
Cc: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	Omar Sandoval <osandov@osandov.com>, Danielle Costantino <dcostantino@meta.com>, kasan-dev@googlegroups.com, 
	Petr Mladek <pmladek@suse.com>, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: song@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SN736VYS;       spf=pass
 (google.com: domain of song@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=song@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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
X-Rspamd-Queue-Id: 2FA6E21601F
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[kernel.org,gmail.com,linux-foundation.org,vger.kernel.org,osandov.com,meta.com,googlegroups.com,suse.com];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBC4ZB2GTVUKBB67UU3GQMGQENLA3YFY];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,mail.gmail.com:mid,mail-dl1-x123a.google.com:rdns,mail-dl1-x123a.google.com:helo]
X-Rspamd-Action: no action

On Thu, Mar 5, 2026 at 8:16=E2=80=AFAM Breno Leitao <leitao@debian.org> wro=
te:
>
> The watchdog_ts name doesn't convey what the timestamp actually tracks.
> This field tracks the last time a workqueue got progress.
>
> Rename it to last_progress_ts to make it clear that it records when the
> pool last made forward progress (started processing new work items).
>
> No functional change.
>
> Signed-off-by: Breno Leitao <leitao@debian.org>

Acked-by: Song Liu <song@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APhsuW4Z1XGZV3A7gwt6X6K-4VjbS2uBG3FbF7u9BK%2BMKO-7sg%40mail.gmail.com.
