Return-Path: <kasan-dev+bncBCUY5FXDWACRBVXVZ3FQMGQEJ6UZRFA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IIa7Atm6c2kmyQAAu9opvQ
	(envelope-from <kasan-dev+bncBCUY5FXDWACRBVXVZ3FQMGQEJ6UZRFA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 19:15:53 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 71D1F7972C
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 19:15:52 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-47ee8808ffbsf18297705e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 10:15:52 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769192152; cv=pass;
        d=google.com; s=arc-20240605;
        b=G4tYwE5UkQkE/4fn58ruXigetGdYujC+E3Rj3dIHZQ+gxh5Piz7YDBI7/lNGvr86JF
         XtuZ/csQB6nqYknCcbuzwT9is3CgPwvy+l83lDp0zBjo+HKfRdedyVzjI1eNNZPLcKov
         yqhp44EF/EAr5RKmSLxqgvDRd1FGnJ1sD2FjyuMospkMNcsnQy3fPKKQ2KONr4vA15lX
         oCeE/5YLOaJGeTs6i1LL25tOLl7VPM6rdyeJVA8sbnt/Qnj8wjx00S9yTTX6R37gZiRF
         9bpjFNd7rSuyIlzAFK176Rn6OxFd8xAJR2J4nIL5k8zQdcGjuU0ZUPfiBLIU7EhdWKo0
         ACbw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+HAlUrNI6IoR1ngfmTnVPUh/4KGCoTrVq0GrdA9blzM=;
        fh=UfenH0HMH4hErVzC4XYlIyNmIYipm2eklC9KSPzxMsk=;
        b=cHEVUcIEMR+u43Obq8Epg65YhCtgyfXdh8UjKGyHEdHOrmADRbKQr1RZOuQdD+ohYU
         1RtX9HNe19r5kNtmmr+zym0akFX21dliLYi+XK2blDU8SETAwA4MEaokGTE7r5Vf66kX
         RyWORV34BTEB3qsS2C9pafFUlqBreSyTucwZz7UriOyAdp9d3je4nRkoEihmSmMDlsgT
         BLiPALcELBSJ3dtNPe1BpmsPzxbWEeimG6c47p+2v+a9aCa2fNE7xuSOmD+c/obximSx
         5+hn/yzN0gXyCLI+nuCmMRRgageDo214GHbrxuqUwfHYfLRP10VgnhGfH1zgB3q8P73t
         /kPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BuqTdjLK;
       arc=pass (i=1);
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769192152; x=1769796952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+HAlUrNI6IoR1ngfmTnVPUh/4KGCoTrVq0GrdA9blzM=;
        b=pThn0kqjh+/hWcjJ9JjrL49IhQJxTX5vuypa8Mxax9a1/j9TvcWH1hxI0/iB1+g6nJ
         y01MjJrhPBYiZJbXN+RrDSfsxdPKvsBqvcLIdzHdOPfAmC4nDwZAbWQWPPSqbnJJNT5q
         VGiamLoXO1QbFdCQnMWgCtObCE5t3VJRhuDL+oz+PmgqG+dmqxI80EmLmCg/lLZqQ9hT
         zdZC4bkEJWvSonmOnWn2WhMWBzNzMNoqRK7Ub1xCpuVn45TVDuK56T4uyBb8REdAel41
         kQDFg3XQ+wwOf+0/GUHBA1M/DW4CFpxJoCnkHEOomY7RcptRhjQmQDKhyWzyjmgoyKVD
         sftA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769192152; x=1769796952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+HAlUrNI6IoR1ngfmTnVPUh/4KGCoTrVq0GrdA9blzM=;
        b=TIiKLmS/K9RXcCL6mokPqliGHtoVAzzuzoRfz41zm9OhyrOAxYp0Kec+gcHYKtH0lu
         XS6/MJzNllaNgOOpH8ZbJrKu+FSe5PALeV7K7ALz6gjj7nhx24DgyyW5/S4t2AFhiLo+
         J3/g9mypNRQGEgrJnOLRhfOctk3IFZrnAD+mt8dqkCobbQAf3JZY6u3ldCPApa1hhWZu
         OzbLuSzuiY1sUGprndhBHUu6qi5j0EfdA1HdqJwZN+Pc02G2LSF7CXJHEDTuGFv9QS+a
         smEFZsbFg8wZTaf7OOPl2+R8pccwxZ28E3ACnyn+8iU3UluoKVz4mdmaudgsKVkyI0L6
         /JGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769192152; x=1769796952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+HAlUrNI6IoR1ngfmTnVPUh/4KGCoTrVq0GrdA9blzM=;
        b=LB7lHUatuLcoSeOwplKDB09TovipucZRkosYyJphiuGzbKstBEtf0wE7+oIlmup04I
         21ZbrO8WcFOs+H3g/mh2w6MSmFjWPvum5r7Ez4u1OV1bOHKvFnScHV6kTcIRoSPauN+F
         3LXUKPdWoOGW6wHCQWfxP7BKAuZHi2sa6a71OMc5TIBb1flWz0LCj65UaGb0+m0wjIht
         nxIBGY9nup0JR3AbA8Eq+gxwubdcUZdxwzofOqctwIKg0CRyLcluJJAzyt6W03t784HZ
         JOyGXNrXZwYPeQCHGh2UU4V4+i1W/BzFvkAQzyWcy+2AZyDxQyvAd/pINBnpUFTDjZ9U
         hUEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUfqRtNVAClhOGIvGyFMme9PeTgOQWhhp1nhhtCkpj6KMijahQMbQ0G8VN3drY2scueL9w6mA==@lfdr.de
X-Gm-Message-State: AOJu0Ywn4Q0YHc7AIr6iUTfgvVdkLuTeE5/CSXriFgjdj/fWaYfz7QIZ
	So4vJySD7NnPg3cjoVEerYGU8DbsDc6nb5M0GmpnwHHH86i2zA+HDMdJ
X-Received: by 2002:a05:600c:4692:b0:477:55c9:c3ea with SMTP id 5b1f17b1804b1-4804c9ca73amr72985105e9.35.1769192151471;
        Fri, 23 Jan 2026 10:15:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GRvWcf9joJeieMHET70dvu8nwI8YMSctRKFEozBw5+zw=="
Received: by 2002:a05:600c:1c0e:b0:475:c559:4e89 with SMTP id
 5b1f17b1804b1-48046fc4708ls16999425e9.2.-pod-prod-03-eu; Fri, 23 Jan 2026
 10:15:48 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVpYwnFchmLn5KiQhk7yTwnZkGsecpwLViGnxJnTCHdnS9emVHZYjphlvthy4JBKUtNtlFVCsszt3M=@googlegroups.com
X-Received: by 2002:a05:600c:4f48:b0:477:63b5:6f76 with SMTP id 5b1f17b1804b1-4804c9b8854mr69687685e9.25.1769192148675;
        Fri, 23 Jan 2026 10:15:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769192148; cv=pass;
        d=google.com; s=arc-20240605;
        b=HM4OUKS1H/Nw91dzU/GYOlyAUNceQwriOcHLd6ouSapTYMToa6Onl0fzEhznITHmem
         UKzXKLXbgjr6hXnXO+xR1SEifR9hg7TyRMjwxVkIMpr0Dw91WmrpGg+eeA7+5pKsBzgF
         sj67HnWJUsuAn/9ux4y6KXUY0DCDRta6fW+FT50L1/3jUERbKniGXLOydPOBECxmEaZ/
         /IueH3CVmwe5auUBWy0DwnyyXtjjiVDemC/5oB6djrIZDwEVyFy734NGyBN2e7k++6dP
         pvWgIJ+3IHx4k0CWo1+M55JFnzoa+xrqQGPn4WB+uGoZxBB+UHtUwir02C/d6JmDfd/T
         fJaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=I2nG00qw2ruBawht6GJzw6X6qOS/2LLsPM2l8lgx1yM=;
        fh=enzQeOtMeHmAqpVWpU9lF0ydaQhM1ixEvZobhmdsAR0=;
        b=iO2gu8eLi8bgo7/b2ECXo5Gk4jBW+gdnbLFl+r2i8wUMKynKtXqQAgZPzIN/drUTeW
         aZQ/80TO5eJu/kNynLRyEqEcE6TquHHnF4G7jZtpGgWCUgHwLG4eCou1SiAUI7dxtIX5
         Z5xyXcpuU1mFhvfo8xGRsddeqqo7Lipd484/YyasleJg4tPFSuBIqnBd3Xj3zDK24F7U
         Gi7yl3bMFU4ekFmQy4uEq4tMFJM0hHttOzVgQpM8cAIq+ChEM4NROjF15EFTs8Pc1fxV
         Cjbz/2pOD5T8tvkEgdDSnosZoojMKYscZgwapSK695SO4NTlU+aCu5lFaT/uOCgXLGWD
         9Tdw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BuqTdjLK;
       arc=pass (i=1);
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4804d5f2db1si234285e9.1.2026.01.23.10.15.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Jan 2026 10:15:48 -0800 (PST)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-432755545fcso1819125f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 23 Jan 2026 10:15:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769192148; cv=none;
        d=google.com; s=arc-20240605;
        b=BZUDtVe5zHyA29uuyQGw7DXBflgwIY/OTfM1wUagdngOiuKD+fGLNpiUvtDLkIQCPN
         g+Qe4VoKpOcuN9XEJjvLM+nKN8lBXwnRF2HR+evz80FwmcCehCjt+h169peJ0CyRkzbp
         Pozb0vwTqJrhxLP82qiC84M17chwUfHSkgmgRzAKJClWltajz0pETPPbBUY5NNgyLmlB
         Mvedal63QeX2QR37HlysuP0rKHhpTWvX2rudpMbuWkCUl8fYj5bYTQoWXh/kCbbiDUKT
         0Y6B7yhjqcAayDH9HwejJqMR2BPhkqEhA5K1voH7k2PILeep3R2/9OtagtGJAFTIpql0
         zeJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=I2nG00qw2ruBawht6GJzw6X6qOS/2LLsPM2l8lgx1yM=;
        fh=enzQeOtMeHmAqpVWpU9lF0ydaQhM1ixEvZobhmdsAR0=;
        b=gKM1B/PoPdSsLScfOXXReJU4B9tTBaV6404YJZNhrdL7OVyP9oiHkHKiJDWyw7yTZw
         33rM6YcnUZhLjdQjImQibzfcJgzmT746BM/mqapZDEQXilr8eztUmfwPdIDVg4kunX9p
         72SXd8V5dTDdZ5UpJgiPASGikCucHKH1KfcrHyq04evHhuutcTMiiEtz9vR7TJ+m/KEb
         bEbSJaFEjmtF/Hr0gCC8c+7WesyRp4/j5Vx4u8BRzZOlgutIqCdBLOQgVyMbq5XHkfDG
         ypMDRb6+wSggvRcKaveZT2+Y30rHrTZ9o0GOCusXq3l6kocjkxe18Iji/uEF3LJPLBvw
         R61Q==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXjf9t5eHQSrvASjV+tPQjgNI1J3WKZ7wkQOEcx2KBqyMwO6y59QVQPoZOkbVeAq+1A4XZjwxfOp/k=@googlegroups.com
X-Gm-Gg: AZuq6aJMvi9/3Djz/+Ory2NHMG9atcJMEk5DO2vqEgWACeZIqfkbOktOQvnfyZmtGeB
	GYR2jnM8J8apGPCH8meYe9pMCw2bnk7jES8Dk0do89h5UydYFxhK85aSPJjdoq57eP+8iF383Jb
	ZIUT1geGpT+LYuFxEmJg/rR7jYzn4uT5nCzneG0xM8Qp48bOs93bsC//JIEzV8GlwT4K+WP/EmJ
	USCsC9vT60pQzBEIDypV3COBkVNP5rCqOqAEidGoam9P+3elm6cq/luKLwZPkKj0n4pwYaftc+u
	1xXxeba/HaPJp2NxxIyCgaAhCTF6705C4fyCPmIRxunOU3aSee+XsWxRsTa8v3OJ5PLOqe8V
X-Received: by 2002:a05:6000:607:b0:435:8f88:7226 with SMTP id
 ffacd0b85a97d-435b15fb134mr7443178f8f.40.1769192147696; Fri, 23 Jan 2026
 10:15:47 -0800 (PST)
MIME-Version: 1.0
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz> <20260123-sheaves-for-all-v4-13-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-13-041323d506f7@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 23 Jan 2026 10:15:35 -0800
X-Gm-Features: AZwV_QjgW82i1crlpndwrb8M8pt69fP2CoWaYroMilL8QIj30Jgt-nfZQ9Vffac
Message-ID: <CAADnVQLEupQB3O1RzFAPoVvg-frojmjFQhisAUcxTJOmkz02nw@mail.gmail.com>
Subject: Re: [PATCH v4 13/22] slab: remove the do_slab_free() fastpath
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	"open list:Real-time Linux (PREEMPT_RT):Keyword:PREEMPT_RT" <linux-rt-devel@lists.linux.dev>, bpf <bpf@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BuqTdjLK;       arc=pass
 (i=1);       spf=pass (google.com: domain of alexei.starovoitov@gmail.com
 designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TO_DN_ALL(0.00)[];
	TAGGED_FROM(0.00)[bncBCUY5FXDWACRBVXVZ3FQMGQEJ6UZRFA];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[alexeistarovoitov@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,oracle.com:email,mail.gmail.com:mid,mail-wm1-x33f.google.com:helo,mail-wm1-x33f.google.com:rdns]
X-Rspamd-Queue-Id: 71D1F7972C
X-Rspamd-Action: no action

On Thu, Jan 22, 2026 at 10:53=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> We have removed cpu slab usage from allocation paths. Now remove
> do_slab_free() which was freeing objects to the cpu slab when
> the object belonged to it. Instead call __slab_free() directly,
> which was previously the fallback.
>
> This simplifies kfree_nolock() - when freeing to percpu sheaf
> fails, we can call defer_free() directly.
>
> Also remove functions that became unused.
>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

...

> @@ -6557,7 +6429,12 @@ void kfree_nolock(const void *object)
>                         return;
>         }
>
> -       do_slab_free(s, slab, x, x, 0, _RET_IP_);
> +       /*
> +        * __slab_free() can locklessly cmpxchg16 into a slab, but then i=
t might
> +        * need to take spin_lock for further processing.
> +        * Avoid the complexity and simply add to a deferred list.
> +        */
> +       defer_free(s, x);

We'll re-benchmark this when it lands.
The current defer_free() path due to slab !=3D c->slab is causing
spikes in some of the workloads.
I think with sheaves
slab_nid(slab) =3D=3D numa_mem_id() -> free_to_pcs()
path should be exercised a lot more often and fall back to defer_free()
should be rare.
Just leaving a mental note.

Acked-by: Alexei Starovoitov <ast@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQLEupQB3O1RzFAPoVvg-frojmjFQhisAUcxTJOmkz02nw%40mail.gmail.com.
