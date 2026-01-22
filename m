Return-Path: <kasan-dev+bncBAABB7F6Y3FQMGQE7L7HEFQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WKqiI36fcWmgKQAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB7F6Y3FQMGQE7L7HEFQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 04:54:38 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CA6061814
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 04:54:38 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-655b10ed8d1sf1671829a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 19:54:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769054077; cv=pass;
        d=google.com; s=arc-20240605;
        b=S5kBVuxH+ELSeUwkPpGA9j4FOcJ0l+JQajG/GdQxzPjITSasZ4o1AfoQLPISOG4TMu
         3l+3lWpL+ZzxFzT5CdbTteASg011XoGr1s/APMm55LEwXV0cSAKyCwcOOnsY9Shh/1O6
         I7Q8ZAIOMLtXf3W3Ba/kduQGrAEu/eAgHrWkAem/kQh32pEVluJ2BkpzI8WDqycg5LNv
         aSU1sl1KvecK0E37OmfaAeIX/FdXhWU5CgLvEk+WbIJMmRrK5mh2iAR2qjBruY/O+cvl
         FIeJGPx1lbqtVM0FVWwpnTGJ7o42+DJYqKJxIfz6NUTyVb1qIzrrDZ9CUQHfBOx/IV76
         GI5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=in8HCYdLTgBUgrzXSh97Rz4WuHRCMViqsHEiCZGB/vw=;
        fh=OhLUO92/TOBrpNNwiGZy6jSfpzDcdS+4GOY7Aux88yY=;
        b=jOUiSWnJTrNw+f2trgBlzKtzid/CSre/7GmNqpHzOVrt51pbOWkHCEFXv0FKwAHw1w
         qyX15NlLleqEGfjicge/ijCTnA9FWoFuJsc/6g6sE2f5a2ucJU2nxwUbTEb814Ynm9RB
         CM5EALfiryOuZ8yDpOm8jgxC46uKaIyq4Jza+8irC6/cT/jhn26EM88AdlRFpRqHrDeg
         44rJtAnF/69nRFatJi/bIGsRGO79AeXN3y0LKIMfpi2ww1SUuP01Mau8rKcP+9/ED0cl
         4YW6hPB2wI1eMsdN6ukoIgEdti7nFuHxjMdbTlHTPOYnUA6RjA+GhFx+Y0xYALaefDVA
         cfuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Q9wgSQgA;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.173 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769054077; x=1769658877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=in8HCYdLTgBUgrzXSh97Rz4WuHRCMViqsHEiCZGB/vw=;
        b=aVi83VPZkIk7wzAJ6mm5mTJ8oawmHX4X+3puew8VIxc9Gt2urVLbOFnrpUZc4SDHzI
         rCgVHPae6W7pkQxq/n73tgWWH9N0HCdc6OoOWvYAEijaHXA8lG+O3tpuRDbZa1KJwADT
         n9bLRU/tVQKxdOUtYu2B67etFKxjpzuWYRB4bE0ux8tvPd8dGTpTAb+vJEvcCcBPO/EA
         jM1FdNYcKMdRykq0zAnVtr3if9ZgQaIaTljQeXScpwySvibCULpCjPn43JC2MaaBc8OK
         LAetd8dhWkoPZWS1ycsYzpUf+wRkr8esdRlr+6Ewq7PqiHOl1tP/TdefBrQueUHYrsXh
         MttQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769054077; x=1769658877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=in8HCYdLTgBUgrzXSh97Rz4WuHRCMViqsHEiCZGB/vw=;
        b=ptG1PwMzXZiS3eU2DwE3y/ZSF7EPo2Q/BKh/0kqoZpCqQYWGaW0S4DYaevhNYl0mrH
         w1h3ojEsqvB3zRsHZ8U5SuCZDligCtd4Dhi+72D9f4w5ijBxhCU7AalJORntRdWoTEw8
         af9vHVYj+9XPhQKVP/3I6tx7c01Pve4gU7l8QEMLFMkBk85RYVLljr+a97vgTh1Po6XZ
         w1zcbnPZEf5qWGLBpLOJxfuQqFATcyJmJ2AVZ2v0seZMuV9kRb4xfbSLAqpPdzKhAKZq
         BfO83w7dtnncXDR3RXL3PlBLrF9RJUVrBMdhk4nNMNzqfxOs8EBzetbq8IdyWnx72EBd
         gODQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhyb9SSa+fBtbY2U8xur+XH4lBD6MzT7Rp03iOLoUNsD54F2yKhMIEWyD5Kp+2fmeaFGdLKQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx4VkrDjljIN+XdMoL1HzZy2ojbRrnZhZjaSmDhI2nnRNiTp3za
	Mb+qO0iZEF1gT5lFBx1q+kCINwzjal7znJH28frFqbFzqMe6/roXRSq4
X-Received: by 2002:a05:6402:f10:b0:64d:4149:4924 with SMTP id 4fb4d7f45d1cf-65832e3fe7fmr796442a12.4.1769054077341;
        Wed, 21 Jan 2026 19:54:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fp1qydgKh9TfgEjm1iCJkOKAfugbJMzUW4hirY6w9BJw=="
Received: by 2002:a05:6402:3043:10b0:647:a582:b819 with SMTP id
 4fb4d7f45d1cf-65832d74541ls211616a12.1.-pod-prod-00-eu; Wed, 21 Jan 2026
 19:54:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW6ygxPLYiJcWAqD7542Qe/Uak+Rp/7UOeYGHGoPq7WSU8FXj6Og7myA0ni+v7CwLsU5EqSCdk7A/s=@googlegroups.com
X-Received: by 2002:a05:6402:518f:b0:649:a157:3327 with SMTP id 4fb4d7f45d1cf-65832ea17c1mr1005264a12.17.1769054075490;
        Wed, 21 Jan 2026 19:54:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769054075; cv=none;
        d=google.com; s=arc-20240605;
        b=coYZpbnhZSPMBYaTC21jyKtk3acpkJX5+wIMuLBd+p5Pnq14b33DeZzQdzZa/5Cd27
         UToZw97IbzYRtCs/UZbyAX4vXVmPx1ly1r3CjDljw9ryZ38v0EduOi0xotUkdgBYSW3V
         C7RnIZygf0UTFIq238BqJiwvCCOS/XOPHkvVo4N7Lp67/u4unFJIIWmDg5BE1T6d5Rt8
         7XsxcHjGbve2mBcSY/yFxs9orLa+AYNbz/TiTZ4GujFkSJgNqu2wAcTL3HkLBlZesLms
         W0TAKZtA6oJjJ5oJbdY3OGXdZxmRRUb+Fr4YjUN97kjpwLAZ6X5EnD6TDjtAjZ6Tpol9
         Hlyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=vw444WMHV1aHVgp9YPBVa4B3NTBF6Yg7X7f7oG/aDTQ=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=h2kOkMmi7imC6BzTsNPh3//BgHEucyfuqSffqsUfItv4bBSexB2CuXrpxgjs/5lLC7
         WRWsj8FyA67DP/AZVwRAfM2T4j7/Hzlo3S4A2imZDGLgDi7Kfn/xzDkMDJHQtH/IPJRR
         DqFiBybbWiF3NKEU2zSB/Q1VtCH1ei6JQ5Nui435QkdKDlZ2JNgHQY3lRuPTpYSg0JR3
         qxb5bc1uhMPlilYAYfy4mGObYH8Zbic7yQhTyWgyTukst6QTRPUdKdCad8TGYO5OHuGN
         rwevi9CBpjcLhutytlRFDp6gebijg27XPFIVU92qa/Ec6yoziai0o31sUSTHRGmsYXKj
         qNpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Q9wgSQgA;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.173 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta0.migadu.com (out-173.mta0.migadu.com. [91.218.175.173])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65822b1d664si63579a12.6.2026.01.21.19.54.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 19:54:35 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 91.218.175.173 as permitted sender) client-ip=91.218.175.173;
Date: Thu, 22 Jan 2026 11:54:24 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 18/21] slab: update overview comments
Message-ID: <ki4y2wnhznq5s25hic2j25ohgxzjae3y7pkjjjkle75hp34e25@juljp5mukkfz>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-18-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-18-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Q9wgSQgA;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 91.218.175.173 as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TO_DN_SOME(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	MISSING_XM_UA(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBAABB7F6Y3FQMGQE7L7HEFQ];
	DKIM_TRACE(0.00)[googlegroups.com:+]
X-Rspamd-Queue-Id: 0CA6061814
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:38PM +0100, Vlastimil Babka wrote:
> The changes related to sheaves made the description of locking and other
> details outdated. Update it to reflect current state.
> 
> Also add a new copyright line due to major changes.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 141 +++++++++++++++++++++++++++++---------------------------------
>  1 file changed, 67 insertions(+), 74 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ki4y2wnhznq5s25hic2j25ohgxzjae3y7pkjjjkle75hp34e25%40juljp5mukkfz.
