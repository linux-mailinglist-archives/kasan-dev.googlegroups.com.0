Return-Path: <kasan-dev+bncBC7OD3FKWUERBVFWYTFQMGQERMOLH5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CGo2IFcbcWmodQAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OD3FKWUERBVFWYTFQMGQERMOLH5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 19:30:47 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF2F65B498
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 19:30:46 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-353049e6047sf116581a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 10:30:46 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769020245; cv=pass;
        d=google.com; s=arc-20240605;
        b=bptSfsh8SxdaopkXmWz3orAvKtqSQ4VIP61g6DpJIlHSkA2ruAzmKweOpPJkh+APzn
         2BknVpsYbvbTDABaLfM4plUv6WHMcWxNE11EsoiJkOFxdQ7X1lRJ7T1WYqjAYjIytf8s
         cVM2wObJThWzOM0cU0DaMdCh+F1Id0ZE7Bcunx+dVhDDhIjDzt/V+I1pnI+cC6LwoDJP
         UvmPpZQu4PDeobml+fr1KSLgTqXp2P1eqQZmm1QO5DDtaMiycuEjrR01DJb8fy0e7SIG
         1b1ZBElpkD5pk9n3vQoAXS+H2f1LSfR7Kx2UsW+5Xw9EstXxDpoMhKn2hPsgLCgzC3vF
         UuRg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U1objul6UREWCBeUDJPBOodlqZLo3/MKUBd+cTQ288k=;
        fh=tMDXlKeNAkamfphhKknF0xWRW/B6ks9WscRL7mRERAE=;
        b=dmR4d9xrYbPqsLqfHq3FQXNAzhMhKLdEyUEmpY9fhdgb1hjdG306h+usKkorUna9KO
         CPJXXLGcmO3py6jsBFITvf1NWa8Ayb/nmDz0ihUY9Ng1j00JqiWYwHBjEkmiyGP0Iw0L
         VwVLfoeDN0LkupXlkQiDrpBLcJnsYsOJFFRa0nKX60qCGT/UbITx0mfhpfzHjSKo+owk
         tUAo57GH1v8n4uuw6GVU/aCsYrdEQcEIU83Rox39awtobIJIXoF7G06Sgwu6+pjKsFe7
         VAeGdtUN5lK65r1ksz7we5RfdDjAi/SwkonJS/s2Xm82xTxogzXgxneEnv30lD8UoSIM
         vlAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jtOXKalZ;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769020245; x=1769625045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=U1objul6UREWCBeUDJPBOodlqZLo3/MKUBd+cTQ288k=;
        b=IuCBdqUB+1gYR88SjmqZ+mZ8SPJGFsjYDSeonB8HDMSBqZKghID4VvmulOUcjxrfyz
         aEoGsk+kPcaneQed/d0jVeISfcghfbJVOes9BJ5CK3BnlJSLp7ncUrVti6wcAbqDuL6T
         gS3kMxcGLR8oFvgEiOLlIUZ2y3sOqyW4NuIgXN96apzEmaCvsdvZDDJLMqDBBmO6wfUp
         AYicNdP8mru7Far6QCH2gcjfp7SNoI3r0anYWuSYPh0Y4nwrxnSvYCtRB9kcnootj2mb
         ghyK+1zWS2KmeMg/SCGydFameed9s2ylfhyEKWLndrVldZtgGfKPUWsLJuBTZiur5mRr
         Xv6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769020245; x=1769625045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=U1objul6UREWCBeUDJPBOodlqZLo3/MKUBd+cTQ288k=;
        b=iT3Ga6E9D9oHZtWlVYTS3caZlQjAVyW3s25/sKuNrE2IXuhR2TXcVNTki+PERbVHqW
         wfghaPDm4fXauvPK9URHgaIMANdVbYii4YNosoRhdbm/lzxS9coxO4+k8eujes7SYm1P
         +ByVx8mLIg9s07DnaVyywkDAV29hiQqV1seTDeucluxgKNkVOdTf3n8a6xB2RvreOF3p
         WXLQf7G+M9RzWwct6T9ny6vvbag1knwDzu5Ielvd98EKXlvWSCmHY7VkwlcB0wPjcA0b
         3hbToqZu8aUCUB0EWQj89Dourb0GwC53mtKr8p2GGvagx24JPDgziIzQ0nX63k7bebng
         e8tQ==
X-Forwarded-Encrypted: i=3; AJvYcCXG1ZfssP/EKge/WJNJDXXPOTzrVxSNHb4cIUmpOiuk60M7CssIDCnaz5uUU6a7C4Yd4gebwA==@lfdr.de
X-Gm-Message-State: AOJu0Yy0SlB2n3sdds2xIUcKX4cjSyMKxm+YO6tWtuYvkxh5+pSqvAkf
	b06XbsJ1WScuhkHdyM5pQofi19FMSsy2PEWhwnBYEEhp1ij042dBJALY
X-Received: by 2002:a17:903:8cd:b0:2a7:5095:c92a with SMTP id d9443c01a7336-2a75095cc58mr59114755ad.31.1769020245061;
        Wed, 21 Jan 2026 10:30:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GNpwe/sHHkuWeh4Pt1uruNTRKkgW0QpRtUHvSFf5DCgw=="
Received: by 2002:a17:902:d585:b0:290:8ffc:aa6c with SMTP id
 d9443c01a7336-2a7d350deb9ls768935ad.2.-pod-prod-01-us; Wed, 21 Jan 2026
 10:30:42 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVrIFDQ1VcKCw0BkUHiz4GlrFEuU9BbP23aCTfezCgi+ErNjMBv3ISRoyZxHCzzxzLJvXOp0Ai2phI=@googlegroups.com
X-Received: by 2002:a17:902:c40c:b0:2a1:35df:2513 with SMTP id d9443c01a7336-2a717533c8dmr182936845ad.17.1769020242038;
        Wed, 21 Jan 2026 10:30:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769020242; cv=pass;
        d=google.com; s=arc-20240605;
        b=b0umIQaqRNyOr2EXWkaqmzo10UsIK0nBC1++9IrwCMKD2kOcF/Z1noLDWYV+712+OL
         rqlrxDPyHVORPXoqAKF2SCZ1jSyakRBXq5b32WaZokuRTXEmpu84v6EicuyfCdV7tQJK
         TYAUSa4wIek21Pr1tcXYpK6WeT44rhhlAySv20Fc5WT5qHXkSLkzurB/BSwgu6I6tMUm
         bBziSfuYfYbIIp3ym7qKj2Tx1Ia9EvpWkF6DA1v9DaznnqKfeVP6l6cdpZIBjIVg4/oH
         4xu1TT7333VypKDvOiMH0MvpmG0LJWNt65YDYaLffuGVsqEv6YRhxMQ3DjIkbuYQQR8H
         sPJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hk+loGahu/yMxf2HTXU45I8jZGBJg9jz2G1ZhRfU2lM=;
        fh=WMVjE5qtndf2osIiALWZeJcMSTook7V9h7PejgYo7Gs=;
        b=VmPvY7DqauylbiRbCsxFY1KWZkuHhAEGt2TyoHdhCKlix4kLNmfCJSg4sHg+oKsqb1
         pVZL8pnMTwVPWOvZAeKATRXkavdeO41BNdHKVsov5t8/aa+ZNd9awjGVqrk4wdiNb3xy
         Wv20XM46D8K5cMRWxZyxtChrszPHwZt468hjkpNluhVnO6OyoETbP3/46cpyqNdnDX3T
         QCFlggFngzhBTXnol11q2S7ZU2zEvZqeeZfvWiTKpdKXLP0Xjt2SempW9tvJpYur2WEg
         kb5bL4nZCXXOM/FTybFBsxd6uqhNAApv3SKSYAwLuaeuiW2P0StHecNBZi3Bd1YP7pJJ
         YzyQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jtOXKalZ;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a7190a4bc9si4370995ad.1.2026.01.21.10.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 10:30:42 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id d75a77b69052e-50299648ae9so23751cf.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 10:30:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769020241; cv=none;
        d=google.com; s=arc-20240605;
        b=JGBdz3TOMvDh6pVNTuzTJrnVvWo6P0xLLgpXf5NyztL9yom1wBUWFYhL8FSakGjBuw
         vwWcndjl9erzJmZH0ONqUi6gOzwsX32j1qbui28fv4wq3/VFHoflwY0cjhgZdAtM+IbV
         MhmLsSeeJoKYB2ERasYBvhvB1A1IirCQgtrzEGew2SF4krBBYAWdvA1+cMJDvM8wkWbz
         cD8/tbDGKq1kHEgzswsS50fEU32gMGWNZi9vLRCFTKGS2Rc/m3DhPUSV7H1fSomabX8q
         SpHBNebkcxb8QR3uwHVipB8nig77SIadEHUXWOruE3tp3843pW9MP2NerIzXMEZj+T78
         162A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hk+loGahu/yMxf2HTXU45I8jZGBJg9jz2G1ZhRfU2lM=;
        fh=WMVjE5qtndf2osIiALWZeJcMSTook7V9h7PejgYo7Gs=;
        b=Y7oCwQX76CUXZzG6PdW/vzjm7a+kBo4cIoCK8m7xyEDeeIL5VQbsJ4p6EVpTHKBLlb
         DUaZzFBq9EXNsfzevvvnSshc5tswIGn6z77Sfwp3CtrKdYWZNExgY1U5XobXAcJDjk5u
         BiwczlIMaT8g0iO1l0RYSEq7nBDmDY3w/riebM5+9UmU6zn/7CQI/igTJaJe9sZoE6a1
         K+/nDwkRPjBZFJWgAiqsGZrHN7Cqi/xP0ALmIfcM26CM4a66TujhyMwjkhtACPcGblqJ
         rStx51e4JZasQBgmJYl6s8PPQ51mz6XfPFjxDZd9+23+0YTKca/IBgn6zWtyGA9bNCjb
         AzMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWECSWioETB5tD2kF6Zi0mgjk42rXRcYxsKexNN7fXJlMM1AtodPO/O8hBkBojYjOU/7pSTiyqPdYI=@googlegroups.com
X-Gm-Gg: AZuq6aJoTyj7roiiWCjyWQ1hQ1/aLKFvc63IsnN+BXHaWcdookQe3x8qZ6G+cg9VrO0
	e62O9o0eVakSLk8/Q7wQ/Sho04tLNNY1L6L979+W7C+xJztpxyzQqsJH3lrgfCpAvuaXFIiPGSa
	zxnC2oRfCmnkDACjUcrCmZR65BzG/fbFo7ixrBRZhy6SuA5k1Nr5ubKezYi1Vv+Uc8AqTRpe/xS
	lRwhg6zFv5zzxPtTVmQR1zNlTBwz9Xgax/rK9tQFrLgRaMB2ltAiEVpEj167VhYV+UTCiizB3Vf
	gzC8M8jlsAmj7dB5nysUDNk=
X-Received: by 2002:a05:622a:1825:b0:4f3:54eb:f26e with SMTP id
 d75a77b69052e-502ebddf1damr405151cf.1.1769020240526; Wed, 21 Jan 2026
 10:30:40 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 18:30:28 +0000
X-Gm-Features: AZwV_QgJsx28PWNy6MDtA7PMODlO-XxW0gxWFH0Lcu8zvlUQSetLY7ny4kvP86A
Message-ID: <CAJuCfpHi_WqPkWvQuDqg3L1FNeV-P=E52uCakBCXz1AFmkHf=Q@mail.gmail.com>
Subject: Re: [PATCH v3 17/21] slab: refill sheaves from all nodes
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jtOXKalZ;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OD3FKWUERBVFWYTFQMGQERMOLH5I];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[surenb@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid]
X-Rspamd-Queue-Id: EF2F65B498
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 2:41=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> __refill_objects() currently only attempts to get partial slabs from the
> local node and then allocates new slab(s). Expand it to trying also
> other nodes while observing the remote node defrag ratio, similarly to
> get_any_partial().
>
> This will prevent allocating new slabs on a node while other nodes have
> many free slabs. It does mean sheaves will contain non-local objects in
> that case. Allocations that care about specific node will still be
> served appropriately, but might get a slowpath allocation.
>
> Like get_any_partial() we do observe cpuset_zone_allowed(), although we
> might be refilling a sheaf that will be then used from a different
> allocation context.
>
> We can also use the resulting refill_objects() in
> __kmem_cache_alloc_bulk() for non-debug caches. This means
> kmem_cache_alloc_bulk() will get better performance when sheaves are
> exhausted. kmem_cache_alloc_bulk() cannot indicate a preferred node so
> it's compatible with sheaves refill in preferring the local node.
> Its users also have gfp flags that allow spinning, so document that
> as a requirement.
>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> ---
>  mm/slub.c | 137 ++++++++++++++++++++++++++++++++++++++++++++++++--------=
------
>  1 file changed, 106 insertions(+), 31 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index d52de6e3c2d5..2c522d2bf547 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2518,8 +2518,8 @@ static void free_empty_sheaf(struct kmem_cache *s, =
struct slab_sheaf *sheaf)
>  }
>
>  static unsigned int
> -__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int=
 min,
> -                unsigned int max);
> +refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int m=
in,
> +              unsigned int max);
>
>  static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
>                          gfp_t gfp)
> @@ -2530,8 +2530,8 @@ static int refill_sheaf(struct kmem_cache *s, struc=
t slab_sheaf *sheaf,
>         if (!to_fill)
>                 return 0;
>
> -       filled =3D __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
> -                       to_fill, to_fill);
> +       filled =3D refill_objects(s, &sheaf->objects[sheaf->size], gfp, t=
o_fill,
> +                               to_fill);
>
>         sheaf->size +=3D filled;
>
> @@ -6522,29 +6522,22 @@ void kmem_cache_free_bulk(struct kmem_cache *s, s=
ize_t size, void **p)
>  EXPORT_SYMBOL(kmem_cache_free_bulk);
>
>  static unsigned int
> -__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int=
 min,
> -                unsigned int max)
> +__refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigne=
d int min,
> +                     unsigned int max, struct kmem_cache_node *n)
>  {
>         struct slab *slab, *slab2;
>         struct partial_context pc;
>         unsigned int refilled =3D 0;
>         unsigned long flags;
>         void *object;
> -       int node;
>
>         pc.flags =3D gfp;
>         pc.min_objects =3D min;
>         pc.max_objects =3D max;
>
> -       node =3D numa_mem_id();
> -
> -       if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> +       if (!get_partial_node_bulk(s, n, &pc))
>                 return 0;
>
> -       /* TODO: consider also other nodes? */
> -       if (!get_partial_node_bulk(s, get_node(s, node), &pc))
> -               goto new_slab;
> -
>         list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
>
>                 list_del(&slab->slab_list);
> @@ -6582,8 +6575,6 @@ __refill_objects(struct kmem_cache *s, void **p, gf=
p_t gfp, unsigned int min,
>         }
>
>         if (unlikely(!list_empty(&pc.slabs))) {
> -               struct kmem_cache_node *n =3D get_node(s, node);
> -
>                 spin_lock_irqsave(&n->list_lock, flags);
>
>                 list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_lis=
t) {
> @@ -6605,13 +6596,92 @@ __refill_objects(struct kmem_cache *s, void **p, =
gfp_t gfp, unsigned int min,
>                 }
>         }
>
> +       return refilled;
> +}
>
> -       if (likely(refilled >=3D min))
> -               goto out;
> +#ifdef CONFIG_NUMA
> +static unsigned int
> +__refill_objects_any(struct kmem_cache *s, void **p, gfp_t gfp, unsigned=
 int min,
> +                    unsigned int max, int local_node)
> +{
> +       struct zonelist *zonelist;
> +       struct zoneref *z;
> +       struct zone *zone;
> +       enum zone_type highest_zoneidx =3D gfp_zone(gfp);
> +       unsigned int cpuset_mems_cookie;
> +       unsigned int refilled =3D 0;
> +
> +       /* see get_any_partial() for the defrag ratio description */
> +       if (!s->remote_node_defrag_ratio ||
> +                       get_cycles() % 1024 > s->remote_node_defrag_ratio=
)
> +               return 0;
> +
> +       do {
> +               cpuset_mems_cookie =3D read_mems_allowed_begin();
> +               zonelist =3D node_zonelist(mempolicy_slab_node(), gfp);
> +               for_each_zone_zonelist(zone, z, zonelist, highest_zoneidx=
) {
> +                       struct kmem_cache_node *n;
> +                       unsigned int r;
> +
> +                       n =3D get_node(s, zone_to_nid(zone));
> +
> +                       if (!n || !cpuset_zone_allowed(zone, gfp) ||
> +                                       n->nr_partial <=3D s->min_partial=
)
> +                               continue;
> +
> +                       r =3D __refill_objects_node(s, p, gfp, min, max, =
n);
> +                       refilled +=3D r;
> +
> +                       if (r >=3D min) {
> +                               /*
> +                                * Don't check read_mems_allowed_retry() =
here -
> +                                * if mems_allowed was updated in paralle=
l, that
> +                                * was a harmless race between allocation=
 and
> +                                * the cpuset update
> +                                */
> +                               return refilled;
> +                       }
> +                       p +=3D r;
> +                       min -=3D r;
> +                       max -=3D r;
> +               }
> +       } while (read_mems_allowed_retry(cpuset_mems_cookie));
> +
> +       return refilled;
> +}
> +#else
> +static inline unsigned int
> +__refill_objects_any(struct kmem_cache *s, void **p, gfp_t gfp, unsigned=
 int min,
> +                    unsigned int max, int local_node)
> +{
> +       return 0;
> +}
> +#endif
> +
> +static unsigned int
> +refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int m=
in,
> +              unsigned int max)
> +{
> +       int local_node =3D numa_mem_id();
> +       unsigned int refilled;
> +       struct slab *slab;
> +
> +       if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> +               return 0;
> +
> +       refilled =3D __refill_objects_node(s, p, gfp, min, max,
> +                                        get_node(s, local_node));
> +       if (refilled >=3D min)
> +               return refilled;
> +
> +       refilled +=3D __refill_objects_any(s, p + refilled, gfp, min - re=
filled,
> +                                        max - refilled, local_node);
> +       if (refilled >=3D min)
> +               return refilled;
>
>  new_slab:
>
> -       slab =3D new_slab(s, pc.flags, node);
> +       slab =3D new_slab(s, gfp, local_node);
>         if (!slab)
>                 goto out;
>
> @@ -6626,8 +6696,8 @@ __refill_objects(struct kmem_cache *s, void **p, gf=
p_t gfp, unsigned int min,
>
>         if (refilled < min)
>                 goto new_slab;
> -out:
>
> +out:
>         return refilled;
>  }
>
> @@ -6637,18 +6707,20 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s,=
 gfp_t flags, size_t size,
>  {
>         int i;
>
> -       /*
> -        * TODO: this might be more efficient (if necessary) by reusing
> -        * __refill_objects()
> -        */
> -       for (i =3D 0; i < size; i++) {
> +       if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> +               for (i =3D 0; i < size; i++) {
>
> -               p[i] =3D ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
> -                                    s->object_size);
> -               if (unlikely(!p[i]))
> -                       goto error;
> +                       p[i] =3D ___slab_alloc(s, flags, NUMA_NO_NODE, _R=
ET_IP_,
> +                                            s->object_size);
> +                       if (unlikely(!p[i]))
> +                               goto error;
>
> -               maybe_wipe_obj_freeptr(s, p[i]);
> +                       maybe_wipe_obj_freeptr(s, p[i]);
> +               }
> +       } else {
> +               i =3D refill_objects(s, p, flags, size, size);
> +               if (i < size)
> +                       goto error;
>         }
>
>         return i;
> @@ -6659,7 +6731,10 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, =
gfp_t flags, size_t size,
>
>  }
>
> -/* Note that interrupts must be enabled when calling this function. */
> +/*
> + * Note that interrupts must be enabled when calling this function and g=
fp
> + * flags must allow spinning.
> + */
>  int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size=
_t size,
>                                  void **p)
>  {
>
> --
> 2.52.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpHi_WqPkWvQuDqg3L1FNeV-P%3DE52uCakBCXz1AFmkHf%3DQ%40mail.gmail.com.
